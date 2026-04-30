"""
Database Service for Packet Peeper
Handles persistent storage of packets, alerts, and reports
Supports both PostgreSQL and SQLite
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from config.config import DATABASE_URL, DB_ENGINE, PACKET_BUFFER_SIZE, FEATURES

logger = logging.getLogger(__name__)
Base = declarative_base()

# ============== DATABASE MODELS ==============

class PacketRecord(Base):
    """Captured network packet record"""
    __tablename__ = "packets"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    protocol = Column(String(20), index=True)
    src_ip = Column(String(45), index=True)  # IPv4 + IPv6
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    length = Column(Integer)
    service = Column(String(100))
    tcp_flags = Column(Integer)
    payload_hash = Column(String(64))  # SHA256 of payload (for dedup)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'protocol': self.protocol,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'length': self.length,
            'service': self.service,
            'tcp_flags': self.tcp_flags,
        }

class AlertRecord(Base):
    """Security alert record"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    alert_type = Column(String(50), index=True)  # port_scan, ddos, brute_force, etc.
    severity = Column(String(20))  # low, medium, high, critical
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    title = Column(String(200))
    description = Column(Text)
    evidence = Column(Text)  # JSON string
    resolved = Column(Boolean, default=False)
    
    def to_dict(self):
        try:
            evidence_dict = json.loads(self.evidence) if self.evidence else {}
        except json.JSONDecodeError:
            evidence_dict = {}
        
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'title': self.title,
            'description': self.description,
            'evidence': evidence_dict,
            'resolved': self.resolved,
        }

class DeviceRecord(Base):
    """Network device record"""
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, index=True)
    mac_address = Column(String(17))
    hostname = Column(String(255))
    device_type = Column(String(100))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    packets_in = Column(Integer, default=0)
    packets_out = Column(Integer, default=0)
    bytes_in = Column(Integer, default=0)
    bytes_out = Column(Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
        }

class ReportRecord(Base):
    """Generated report metadata"""
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    report_type = Column(String(20))  # pdf, csv, json
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    file_path = Column(String(500))
    total_packets = Column(Integer)
    total_alerts = Column(Integer)
    file_size = Column(Integer)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'report_type': self.report_type,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat(),
            'file_path': self.file_path,
            'total_packets': self.total_packets,
            'total_alerts': self.total_alerts,
            'file_size': self.file_size,
        }

# ============== DATABASE SERVICE CLASS ==============

class DatabaseService:
    """Manages all database operations with connection pooling and error handling"""
    
    def __init__(self):
        """Initialize database connection and create tables"""
        try:
            # Create engine with connection pooling
            engine_kwargs = {
                'pool_size': 10,
                'max_overflow': 20,
                'pool_pre_ping': True,  # Test connections before use
            }
            
            if 'sqlite' not in DATABASE_URL:
                engine_kwargs['pool_recycle'] = 3600  # Recycle connections hourly for PostgreSQL
            
            self.engine = create_engine(DATABASE_URL, **engine_kwargs)
            self.SessionLocal = sessionmaker(bind=self.engine)
            
            # Create all tables
            Base.metadata.create_all(self.engine)
            logger.info(f"[OK] Database initialized: {DB_ENGINE}")
            
        except Exception as e:
            logger.error(f"[ERROR] Database initialization failed: {str(e)}")
            logger.warning("[WARN] Falling back to in-memory storage")
            self.engine = None
            self.SessionLocal = None
    
    @contextmanager
    def get_session(self) -> Session:
        """Context manager for database sessions"""
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized")
        
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {str(e)}")
            raise
        finally:
            session.close()
    
    # ============== PACKET OPERATIONS ==============
    
    def save_packet(self, packet_info: Dict) -> bool:
        """Save a captured packet to the database"""
        if not FEATURES['persistent_storage'] or not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                packet = PacketRecord(
                    timestamp=datetime.fromisoformat(packet_info['timestamp'].replace('Z', '+00:00')) 
                              if 'timestamp' in packet_info else datetime.utcnow(),
                    protocol=packet_info.get('protocol'),
                    src_ip=packet_info.get('src_ip'),
                    dst_ip=packet_info.get('dst_ip'),
                    src_port=packet_info.get('src_port'),
                    dst_port=packet_info.get('dst_port'),
                    length=packet_info.get('length', 0),
                    service=packet_info.get('service'),
                    tcp_flags=packet_info.get('tcp_flags', 0),
                )
                session.add(packet)
            return True
        except Exception as e:
            logger.error(f"Error saving packet: {str(e)}")
            return False
    
    def get_packets(self, 
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   protocol: Optional[str] = None,
                   src_ip: Optional[str] = None,
                   dst_ip: Optional[str] = None,
                   limit: int = 1000) -> List[Dict]:
        """Retrieve packets with optional filtering"""
        if not self.SessionLocal:
            return []
        
        try:
            with self.get_session() as session:
                query = session.query(PacketRecord)
                
                # Apply filters
                if start_time:
                    query = query.filter(PacketRecord.timestamp >= start_time)
                if end_time:
                    query = query.filter(PacketRecord.timestamp <= end_time)
                if protocol:
                    query = query.filter(PacketRecord.protocol == protocol)
                if src_ip:
                    query = query.filter(PacketRecord.src_ip == src_ip)
                if dst_ip:
                    query = query.filter(PacketRecord.dst_ip == dst_ip)
                
                # Sort by timestamp desc and apply limit
                packets = query.order_by(PacketRecord.timestamp.desc()).limit(limit).all()
                return [p.to_dict() for p in packets]
        
        except Exception as e:
            logger.error(f"Error retrieving packets: {str(e)}")
            return []
    
    # ============== ALERT OPERATIONS ==============
    
    def save_alert(self, alert_info: Dict) -> bool:
        """Save a security alert to the database"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                alert = AlertRecord(
                    alert_type=alert_info.get('type'),
                    severity=alert_info.get('severity', 'medium'),
                    source_ip=alert_info.get('source'),
                    destination_ip=alert_info.get('destination'),
                    title=alert_info.get('title'),
                    description=alert_info.get('description'),
                    evidence=json.dumps(alert_info.get('evidence', {})),
                )
                session.add(alert)
            return True
        except Exception as e:
            logger.error(f"Error saving alert: {str(e)}")
            return False
    
    def dismiss_alert(self, alert_id: int) -> bool:
        """Mark an alert as resolved/dismissed"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                alert = session.query(AlertRecord).filter_by(id=alert_id).first()
                if alert:
                    alert.resolved = True
                    return True
                return False
        except Exception as e:
            logger.error(f"Error dismissing alert: {str(e)}")
            return False
    
    def get_alerts(self,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   severity: Optional[str] = None,
                   resolved: Optional[bool] = None,
                   limit: int = 100) -> List[Dict]:
        """Retrieve alerts with optional filtering"""
        if not self.SessionLocal:
            return []
        
        try:
            with self.get_session() as session:
                query = session.query(AlertRecord)
                
                if start_time:
                    query = query.filter(AlertRecord.timestamp >= start_time)
                if end_time:
                    query = query.filter(AlertRecord.timestamp <= end_time)
                if severity:
                    query = query.filter(AlertRecord.severity == severity)
                if resolved is not None:
                    query = query.filter(AlertRecord.resolved == resolved)
                
                alerts = query.order_by(AlertRecord.timestamp.desc()).limit(limit).all()
                return [a.to_dict() for a in alerts]
        
        except Exception as e:
            logger.error(f"Error retrieving alerts: {str(e)}")
            return []
    
    def clear_alerts(self) -> bool:
        """Delete all alerts from database"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                session.query(AlertRecord).delete()
                session.commit()
                logger.info("All alerts cleared from database")
                return True
        except Exception as e:
            logger.error(f"Error clearing alerts from database: {str(e)}")
            return False
    
    # ============== DEVICE OPERATIONS ==============
    
    def update_device(self, device_info: Dict) -> bool:
        """Create or update device record"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                device = session.query(DeviceRecord).filter_by(
                    ip_address=device_info.get('ipAddress')
                ).first()
                
                if device:
                    device.last_seen = datetime.utcnow()
                    device.packets_in += device_info.get('packetsIn', 0)
                    device.packets_out += device_info.get('packetsOut', 0)
                    device.bytes_in += device_info.get('bytesIn', 0)
                    device.bytes_out += device_info.get('bytesOut', 0)
                else:
                    device = DeviceRecord(
                        ip_address=device_info.get('ipAddress'),
                        mac_address=device_info.get('macAddress'),
                        hostname=device_info.get('hostname'),
                        device_type=device_info.get('type'),
                    )
                    session.add(device)
            return True
        except Exception as e:
            logger.error(f"Error updating device: {str(e)}")
            return False
    
    def get_devices(self, limit: int = 1000) -> List[Dict]:
        """Retrieve all tracked devices"""
        if not self.SessionLocal:
            return []
        
        try:
            with self.get_session() as session:
                devices = session.query(DeviceRecord).order_by(
                    DeviceRecord.last_seen.desc()
                ).limit(limit).all()
                return [d.to_dict() for d in devices]
        except Exception as e:
            logger.error(f"Error retrieving devices: {str(e)}")
            return []
    
    # ============== REPORT OPERATIONS ==============
    
    def save_report(self, report_info: Dict) -> bool:
        """Save report metadata"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                report = ReportRecord(
                    report_type=report_info.get('type'),
                    start_date=datetime.fromisoformat(report_info.get('start_date')),
                    end_date=datetime.fromisoformat(report_info.get('end_date')),
                    file_path=report_info.get('file_path'),
                    total_packets=report_info.get('total_packets', 0),
                    total_alerts=report_info.get('total_alerts', 0),
                    file_size=report_info.get('file_size', 0),
                )
                session.add(report)
            return True
        except Exception as e:
            logger.error(f"Error saving report: {str(e)}")
            return False
    
    def cleanup_old_records(self, days: int = 30) -> int:
        """Delete records older than N days"""
        if not self.SessionLocal:
            return 0
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            with self.get_session() as session:
                # Delete old packets
                deleted_packets = session.query(PacketRecord).filter(
                    PacketRecord.timestamp < cutoff_date
                ).delete()
                
                # Delete resolved old alerts
                deleted_alerts = session.query(AlertRecord).filter(
                    and_(AlertRecord.timestamp < cutoff_date, AlertRecord.resolved == True)
                ).delete()
            
            logger.info(f"Cleanup: Deleted {deleted_packets} packets and {deleted_alerts} alerts")
            return deleted_packets + deleted_alerts
        
        except Exception as e:
            logger.error(f"Error cleaning up records: {str(e)}")
            return 0

# ============== SINGLETON INSTANCE ==============
_db_service = None

def get_database_service() -> DatabaseService:
    """Get or create singleton database service"""
    global _db_service
    if _db_service is None:
        _db_service = DatabaseService()
    return _db_service