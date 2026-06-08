"""
Database Service for Packet Peeper
Handles persistent storage of packets, alerts, and reports
Supports both PostgreSQL and SQLite
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean, and_, or_, func, Index
try:
    from sqlalchemy.orm import declarative_base
except ImportError:
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

class UserRecord(Base):
    """User account record for local authentication"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    last_login = Column(DateTime)
    is_admin = Column(Boolean, default=False)
    role = Column(String(20), default="operator", index=True)
    is_active = Column(Boolean, default=True)
    login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    device_info = Column(Text)  # JSON string {mac_address, ip_address, hostname}
    preferences = Column(Text)  # JSON string for user preferences
    
    def to_dict(self):
        try:
            device_info = json.loads(self.device_info) if self.device_info else {}
            preferences = json.loads(self.preferences) if self.preferences else {}
        except json.JSONDecodeError:
            device_info = {}
            preferences = {}
        
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_admin': self.is_admin,
            'role': self.role,
            'device_info': device_info,
            'preferences': preferences,
        }


class UserSessionRecord(Base):
    """User session tracking with token hash"""
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    device_fingerprint = Column(String(64))
    device_info = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime)
    expires_at = Column(DateTime, index=True)

    def to_dict(self):
        try:
            device_info = json.loads(self.device_info) if self.device_info else {}
        except json.JSONDecodeError:
            device_info = {}

        return {
            'id': self.id,
            'user_id': self.user_id,
            'device_fingerprint': self.device_fingerprint,
            'device_info': device_info,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
        }

class TrafficStatRecord(Base):
    """Periodic traffic statistics snapshot"""
    __tablename__ = "traffic_stats"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    total_packets = Column(Integer, default=0)
    tcp_packets = Column(Integer, default=0)
    udp_packets = Column(Integer, default=0)
    icmp_packets = Column(Integer, default=0)
    current_bandwidth = Column(Float, default=0.0)
    peak_bandwidth = Column(Float, default=0.0)
    average_bandwidth = Column(Float, default=0.0)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'total_packets': self.total_packets,
            'tcp_packets': self.tcp_packets,
            'udp_packets': self.udp_packets,
            'icmp_packets': self.icmp_packets,
            'current_bandwidth': self.current_bandwidth,
            'peak_bandwidth': self.peak_bandwidth,
            'average_bandwidth': self.average_bandwidth,
        }

class TrafficFeatureRecord(Base):
    """1-minute traffic feature snapshot for historical analysis & ML training.

    Each row is a summary of all traffic observed in a single 1-minute window.
    This table supports:
      - Historical time-series queries (bandwidth, packet rates over time)
      - ML anomaly detection (feature vectors for Isolation Forest etc.)
      - Trend analysis and reporting

    Estimated storage: ~2-3 MB/day for a typical home network.
    """
    __tablename__ = "traffic_features"

    id = Column(Integer, primary_key=True)
    window_start = Column(DateTime, nullable=False, index=True)
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    tcp_packets = Column(Integer, default=0)
    udp_packets = Column(Integer, default=0)
    icmp_packets = Column(Integer, default=0)
    other_packets = Column(Integer, default=0)
    avg_packet_size = Column(Float, default=0.0)
    unique_src_ips = Column(Integer, default=0)
    unique_dst_ips = Column(Integer, default=0)
    unique_dst_ports = Column(Integer, default=0)
    syn_count = Column(Integer, default=0)
    syn_ack_ratio = Column(Float, default=0.0)
    dns_queries = Column(Integer, default=0)
    arp_packets = Column(Integer, default=0)
    bandwidth_bps = Column(Float, default=0.0)

    def to_dict(self):
        return {
            'id': self.id,
            'window_start': self.window_start.isoformat(),
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'tcp_packets': self.tcp_packets,
            'udp_packets': self.udp_packets,
            'icmp_packets': self.icmp_packets,
            'other_packets': self.other_packets,
            'avg_packet_size': self.avg_packet_size,
            'unique_src_ips': self.unique_src_ips,
            'unique_dst_ips': self.unique_dst_ips,
            'unique_dst_ports': self.unique_dst_ports,
            'syn_count': self.syn_count,
            'syn_ack_ratio': self.syn_ack_ratio,
            'dns_queries': self.dns_queries,
            'arp_packets': self.arp_packets,
            'bandwidth_bps': self.bandwidth_bps,
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
        self.ready = False
        self.error = None
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
            self.ready = True
            
        except Exception as e:
            logger.error(f"[ERROR] Database initialization failed: {str(e)}")
            logger.warning("[WARN] Falling back to in-memory storage")
            self.error = str(e)
            self.engine = None
            self.SessionLocal = None

    def get_status(self) -> Dict:
        """Get database readiness status for health checks."""
        return {
            'ready': self.ready,
            'engine': DB_ENGINE,
            'error': self.error,
        }
    
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
                    payload_hash=packet_info.get('payload_hash'),
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
                    source_ip=alert_info.get('source_ip') or alert_info.get('source'),
                    destination_ip=alert_info.get('destination_ip') or alert_info.get('destination'),
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
                    source_ip=alert_info.get('source_ip') or alert_info.get('source'),
                    destination_ip=alert_info.get('destination_ip') or alert_info.get('destination'),
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
    
    # ============== TRAFFIC STATISTICS OPERATIONS ==============

    def save_traffic_stats(self, stats: Dict) -> bool:
        """Save a traffic statistics snapshot"""
        if not self.SessionLocal:
            return False

        try:
            with self.get_session() as session:
                record = TrafficStatRecord(
                    total_packets=stats.get('total_packets', 0),
                    tcp_packets=stats.get('tcp_packets', 0),
                    udp_packets=stats.get('udp_packets', 0),
                    icmp_packets=stats.get('icmp_packets', 0),
                    current_bandwidth=stats.get('current_bandwidth', 0),
                    peak_bandwidth=stats.get('peak_bandwidth', 0),
                    average_bandwidth=stats.get('average_bandwidth', 0),
                )
                session.add(record)
            return True
        except Exception as e:
            logger.error(f"Error saving traffic stats: {str(e)}")
            return False

    def get_traffic_stats(self,
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          limit: int = 1000) -> List[Dict]:
        """Retrieve traffic stats snapshots"""
        if not self.SessionLocal:
            return []

        try:
            with self.get_session() as session:
                query = session.query(TrafficStatRecord)
                if start_time:
                    query = query.filter(TrafficStatRecord.timestamp >= start_time)
                if end_time:
                    query = query.filter(TrafficStatRecord.timestamp <= end_time)
                rows = query.order_by(TrafficStatRecord.timestamp.desc()).limit(limit).all()
                return [row.to_dict() for row in rows]
        except Exception as e:
            logger.error(f"Error retrieving traffic stats: {str(e)}")
            return []

    def get_bandwidth_history(self, hours: int = 24, limit: int = 2000) -> List[Dict]:
        """Return bandwidth history data points for charts"""
        if not self.SessionLocal:
            return []

        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)
            with self.get_session() as session:
                rows = session.query(TrafficStatRecord).filter(
                    TrafficStatRecord.timestamp >= start_time
                ).order_by(TrafficStatRecord.timestamp.asc()).limit(limit).all()
                return [
                    {
                        'timestamp': row.timestamp.isoformat(),
                        'bandwidth': row.current_bandwidth,
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Error retrieving bandwidth history: {str(e)}")
        return []

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
                    device.packets_in = device_info.get('packetsIn', device.packets_in or 0)
                    device.packets_out = device_info.get('packetsOut', device.packets_out or 0)
                    device.bytes_in = device_info.get('bytesIn', device.bytes_in or 0)
                    device.bytes_out = device_info.get('bytesOut', device.bytes_out or 0)
                    if device_info.get('macAddress'):
                        device.mac_address = device_info.get('macAddress')
                    if device_info.get('hostname'):
                        device.hostname = device_info.get('hostname')
                    if device_info.get('type'):
                        device.device_type = device_info.get('type')
                else:
                    device = DeviceRecord(
                        ip_address=device_info.get('ipAddress'),
                        mac_address=device_info.get('macAddress'),
                        hostname=device_info.get('hostname'),
                        device_type=device_info.get('type'),
                        packets_in=device_info.get('packetsIn', 0),
                        packets_out=device_info.get('packetsOut', 0),
                        bytes_in=device_info.get('bytesIn', 0),
                        bytes_out=device_info.get('bytesOut', 0),
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
    
    # ============== TRAFFIC FEATURE (1-min) OPERATIONS ==============

    def save_traffic_feature(self, feature: Dict) -> bool:
        """Save a 1-minute traffic feature snapshot"""
        if not self.SessionLocal:
            return False
        try:
            with self.get_session() as session:
                record = TrafficFeatureRecord(
                    window_start=feature.get('window_start', datetime.utcnow()),
                    total_packets=feature.get('total_packets', 0),
                    total_bytes=feature.get('total_bytes', 0),
                    tcp_packets=feature.get('tcp_packets', 0),
                    udp_packets=feature.get('udp_packets', 0),
                    icmp_packets=feature.get('icmp_packets', 0),
                    other_packets=feature.get('other_packets', 0),
                    avg_packet_size=feature.get('avg_packet_size', 0.0),
                    unique_src_ips=feature.get('unique_src_ips', 0),
                    unique_dst_ips=feature.get('unique_dst_ips', 0),
                    unique_dst_ports=feature.get('unique_dst_ports', 0),
                    syn_count=feature.get('syn_count', 0),
                    syn_ack_ratio=feature.get('syn_ack_ratio', 0.0),
                    dns_queries=feature.get('dns_queries', 0),
                    arp_packets=feature.get('arp_packets', 0),
                    bandwidth_bps=feature.get('bandwidth_bps', 0.0),
                )
                session.add(record)
                return True
        except Exception as e:
            logger.error(f"Error saving traffic feature: {str(e)}")
            return False

    def get_traffic_features(self,
                             start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None,
                             limit: int = 10080) -> List[Dict]:
        """Retrieve 1-minute traffic feature records (default 7 days = 10080 mins)"""
        if not self.SessionLocal:
            return []
        try:
            with self.get_session() as session:
                query = session.query(TrafficFeatureRecord)
                if start_time:
                    query = query.filter(TrafficFeatureRecord.window_start >= start_time)
                if end_time:
                    query = query.filter(TrafficFeatureRecord.window_start <= end_time)
                rows = query.order_by(TrafficFeatureRecord.window_start.asc()).limit(limit).all()
                return [r.to_dict() for r in rows]
        except Exception as e:
            logger.error(f"Error retrieving traffic features: {str(e)}")
            return []

    def get_traffic_features_aggregated(self,
                                        start_time: datetime,
                                        end_time: datetime,
                                        bucket_minutes: int = 60) -> List[Dict]:
        """Aggregate 1-min traffic features into larger time buckets for charting.

        bucket_minutes: 5, 15, 60, 360, 1440 (1h, 6h, 1d)
        Returns list of dicts with summed/averaged values per bucket.
        """
        if not self.SessionLocal:
            return []
        try:
            with self.get_session() as session:
                rows = session.query(TrafficFeatureRecord).filter(
                    and_(
                        TrafficFeatureRecord.window_start >= start_time,
                        TrafficFeatureRecord.window_start <= end_time,
                    )
                ).order_by(TrafficFeatureRecord.window_start.asc()).all()

            if not rows:
                return []

            bucket_sec = bucket_minutes * 60
            buckets = []
            current_bucket_start = None
            current_rows = []

            for row in rows:
                ts = row.window_start
                bucket_ts = datetime.utcfromtimestamp(
                    (ts.timestamp() // bucket_sec) * bucket_sec
                )
                if current_bucket_start is None or bucket_ts != current_bucket_start:
                    if current_rows:
                        buckets.append(self._aggregate_feature_bucket(current_bucket_start, current_rows))
                    current_bucket_start = bucket_ts
                    current_rows = [row]
                else:
                    current_rows.append(row)

            if current_rows:
                buckets.append(self._aggregate_feature_bucket(current_bucket_start, current_rows))

            return buckets
        except Exception as e:
            logger.error(f"Error aggregating traffic features: {str(e)}")
            return []

    def _aggregate_feature_bucket(self, bucket_start: datetime, rows: list) -> Dict:
        """Aggregate a list of TrafficFeatureRecord rows into a single bucket dict."""
        n = len(rows) or 1
        total_packets = sum(r.total_packets for r in rows)
        total_bytes = sum(r.total_bytes for r in rows)
        return {
            'window_start': bucket_start.isoformat(),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'tcp_packets': sum(r.tcp_packets for r in rows),
            'udp_packets': sum(r.udp_packets for r in rows),
            'icmp_packets': sum(r.icmp_packets for r in rows),
            'other_packets': sum(r.other_packets for r in rows),
            'avg_packet_size': round(total_bytes / max(total_packets, 1), 2),
            'unique_src_ips': max(r.unique_src_ips for r in rows),
            'unique_dst_ips': max(r.unique_dst_ips for r in rows),
            'unique_dst_ports': max(r.unique_dst_ports for r in rows),
            'syn_count': sum(r.syn_count for r in rows),
            'syn_ack_ratio': round(sum(r.syn_ack_ratio for r in rows) / n, 4),
            'dns_queries': sum(r.dns_queries for r in rows),
            'arp_packets': sum(r.arp_packets for r in rows),
            'bandwidth_bps': round(sum(r.bandwidth_bps for r in rows) / n, 2),
            'sample_count': n,
        }

    def get_historical_summary(self, start_time: datetime, end_time: datetime) -> Dict:
        """Compute summary statistics over a time range for dashboard cards."""
        if not self.SessionLocal:
            return {}
        try:
            with self.get_session() as session:
                base = session.query(TrafficFeatureRecord).filter(
                    and_(
                        TrafficFeatureRecord.window_start >= start_time,
                        TrafficFeatureRecord.window_start <= end_time,
                    )
                )

                total_packets = base.with_entities(func.coalesce(func.sum(TrafficFeatureRecord.total_packets), 0)).scalar()
                total_bytes = base.with_entities(func.coalesce(func.sum(TrafficFeatureRecord.total_bytes), 0)).scalar()
                avg_bandwidth = base.with_entities(func.coalesce(func.avg(TrafficFeatureRecord.bandwidth_bps), 0)).scalar()
                peak_bandwidth = base.with_entities(func.coalesce(func.max(TrafficFeatureRecord.bandwidth_bps), 0)).scalar()
                total_alerts = session.query(func.count(AlertRecord.id)).filter(
                    and_(
                        AlertRecord.timestamp >= start_time,
                        AlertRecord.timestamp <= end_time,
                    )
                ).scalar() or 0
                unique_src_ips = base.with_entities(func.coalesce(func.max(TrafficFeatureRecord.unique_src_ips), 0)).scalar()

            return {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'avg_bandwidth_bps': round(float(avg_bandwidth), 2),
                'peak_bandwidth_bps': round(float(peak_bandwidth), 2),
                'total_alerts': total_alerts,
                'unique_src_ips': unique_src_ips,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
            }
        except Exception as e:
            logger.error(f"Error computing historical summary: {str(e)}")
            return {}

    def get_protocol_trend(self, start_time: datetime, end_time: datetime,
                           bucket_minutes: int = 60) -> List[Dict]:
        """Protocol distribution over time for stacked area charts."""
        if not self.SessionLocal:
            return []
        try:
            with self.get_session() as session:
                rows = session.query(TrafficFeatureRecord).filter(
                    and_(
                        TrafficFeatureRecord.window_start >= start_time,
                        TrafficFeatureRecord.window_start <= end_time,
                    )
                ).order_by(TrafficFeatureRecord.window_start.asc()).all()

            if not rows:
                return []

            bucket_sec = bucket_minutes * 60
            buckets = []
            current_bucket_start = None
            current_rows = []

            for row in rows:
                ts = row.window_start
                bucket_ts = datetime.utcfromtimestamp(
                    (ts.timestamp() // bucket_sec) * bucket_sec
                )
                if current_bucket_start is None or bucket_ts != current_bucket_start:
                    if current_rows:
                        buckets.append({
                            'window_start': current_bucket_start.isoformat(),
                            'tcp': sum(r.tcp_packets for r in current_rows),
                            'udp': sum(r.udp_packets for r in current_rows),
                            'icmp': sum(r.icmp_packets for r in current_rows),
                            'other': sum(r.other_packets for r in current_rows),
                            'total': sum(r.total_packets for r in current_rows),
                        })
                    current_bucket_start = bucket_ts
                    current_rows = [row]
                else:
                    current_rows.append(row)

            if current_rows:
                buckets.append({
                    'window_start': current_bucket_start.isoformat(),
                    'tcp': sum(r.tcp_packets for r in current_rows),
                    'udp': sum(r.udp_packets for r in current_rows),
                    'icmp': sum(r.icmp_packets for r in current_rows),
                    'other': sum(r.other_packets for r in current_rows),
                    'total': sum(r.total_packets for r in current_rows),
                })

            return buckets
        except Exception as e:
            logger.error(f"Error computing protocol trend: {str(e)}")
            return []

    def get_top_talkers_history(self, start_time: datetime, end_time: datetime,
                                limit: int = 10) -> List[Dict]:
        """Top talkers by packet count from device records within a time range."""
        if not self.SessionLocal:
            return []
        try:
            with self.get_session() as session:
                devices = session.query(DeviceRecord).filter(
                    and_(
                        DeviceRecord.last_seen >= start_time,
                        DeviceRecord.last_seen <= end_time,
                    )
                ).all()

                talkers = []
                for d in devices:
                    total_packets = (d.packets_in or 0) + (d.packets_out or 0)
                    total_bytes = (d.bytes_in or 0) + (d.bytes_out or 0)
                    talkers.append({
                        'ip_address': d.ip_address,
                        'hostname': d.hostname,
                        'mac_address': d.mac_address,
                        'device_type': d.device_type,
                        'total_packets': total_packets,
                        'total_bytes': total_bytes,
                        'last_seen': d.last_seen.isoformat() if d.last_seen else None,
                    })

                talkers.sort(key=lambda x: x['total_bytes'], reverse=True)
                return talkers[:limit]
        except Exception as e:
            logger.error(f"Error computing top talkers history: {str(e)}")
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
    
    # ============== USER OPERATIONS ==============
    
    def create_user(self, user_data: Dict) -> bool:
        """Create a new user account"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                user = UserRecord(
                    username=user_data.get('username'),
                    email=user_data.get('email'),
                    password_hash=user_data.get('password_hash'),
                    is_admin=user_data.get('is_admin', False),
                    role=user_data.get('role', 'operator'),
                    device_info=json.dumps(user_data.get('device_info', {})),
                    preferences=json.dumps(user_data.get('preferences', {})),
                )
                session.add(user)
            logger.info(f"User created: {user_data.get('username')}")
            return True
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return False
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Retrieve user by username"""
        if not self.SessionLocal:
            return None
        
        try:
            with self.get_session() as session:
                user = session.query(UserRecord).filter_by(username=username).first()
                if user:
                    return {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'password_hash': user.password_hash,
                        'created_at': user.created_at.isoformat() if user.created_at else None,
                        'last_login': user.last_login.isoformat() if user.last_login else None,
                        'is_admin': user.is_admin,
                        'is_active': user.is_active,
                        'role': user.role,
                        'login_attempts': user.login_attempts,
                        'locked_until': user.locked_until.isoformat() if user.locked_until else None,
                        'device_info': json.loads(user.device_info) if user.device_info else {},
                        'preferences': json.loads(user.preferences) if user.preferences else {},
                    }
                return None
        except Exception as e:
            logger.error(f"Error retrieving user: {str(e)}")
            return None

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Retrieve user by email"""
        if not self.SessionLocal:
            return None

        try:
            with self.get_session() as session:
                user = session.query(UserRecord).filter_by(email=email).first()
                if user:
                    return {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'password_hash': user.password_hash,
                        'created_at': user.created_at.isoformat() if user.created_at else None,
                        'last_login': user.last_login.isoformat() if user.last_login else None,
                        'is_admin': user.is_admin,
                        'is_active': user.is_active,
                        'role': user.role,
                        'login_attempts': user.login_attempts,
                        'locked_until': user.locked_until.isoformat() if user.locked_until else None,
                        'device_info': json.loads(user.device_info) if user.device_info else {},
                        'preferences': json.loads(user.preferences) if user.preferences else {},
                    }
                return None
        except Exception as e:
            logger.error(f"Error retrieving user by email: {str(e)}")
            return None

    def get_user_by_identifier(self, identifier: str) -> Optional[Dict]:
        """Lookup a user by username or email."""
        if not identifier:
            return None

        if '@' in identifier:
            return self.get_user_by_email(identifier)

        return self.get_user(identifier)

    def user_exists(self, username: str | None = None, email: str | None = None) -> bool:
        """Check if user exists by username or email"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                if username and email:
                    exists = session.query(UserRecord).filter(
                        or_(UserRecord.username == username, UserRecord.email == email)
                    ).first() is not None
                    return exists
                if username:
                    return session.query(UserRecord).filter_by(username=username).first() is not None
                if email:
                    return session.query(UserRecord).filter_by(email=email).first() is not None
                return False
        except Exception as e:
            logger.error(f"Error checking user existence: {str(e)}")
            return False

    def get_user_count(self) -> int:
        """Return count of users"""
        if not self.SessionLocal:
            return 0

        try:
            with self.get_session() as session:
                return session.query(UserRecord).count()
        except Exception as e:
            logger.error(f"Error counting users: {str(e)}")
            return 0
    
    def update_user(self, username: str, updates: Dict) -> bool:
        """Update user fields"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                user = session.query(UserRecord).filter_by(username=username).first()
                if not user:
                    return False
                
                # Update safe fields
                if 'password_hash' in updates:
                    user.password_hash = updates['password_hash']
                if 'email' in updates:
                    user.email = updates['email']
                if 'is_admin' in updates:
                    user.is_admin = updates['is_admin']
                if 'role' in updates:
                    user.role = updates['role']
                    if 'is_admin' not in updates:
                        user.is_admin = updates['role'] == 'admin'
                if 'is_active' in updates:
                    user.is_active = updates['is_active']
                if 'last_login' in updates:
                    user.last_login = datetime.fromisoformat(updates['last_login']) if isinstance(updates['last_login'], str) else updates['last_login']
                if 'login_attempts' in updates:
                    user.login_attempts = updates['login_attempts']
                if 'locked_until' in updates:
                    user.locked_until = datetime.fromisoformat(updates['locked_until']) if isinstance(updates['locked_until'], str) and updates['locked_until'] else None
                if 'device_info' in updates:
                    user.device_info = json.dumps(updates['device_info'])
                if 'preferences' in updates:
                    user.preferences = json.dumps(updates['preferences'])
            
            return True
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            return False
    
    def get_all_users(self, limit: int = 1000) -> List[Dict]:
        """Retrieve all users (admin function)"""
        if not self.SessionLocal:
            return []
        
        try:
            with self.get_session() as session:
                users = session.query(UserRecord).order_by(UserRecord.created_at.desc()).limit(limit).all()
                return [
                    {
                        'id': u.id,
                        'username': u.username,
                        'email': u.email,
                        'created_at': u.created_at.isoformat() if u.created_at else None,
                        'last_login': u.last_login.isoformat() if u.last_login else None,
                        'is_admin': u.is_admin,
                        'role': u.role,
                        'is_active': u.is_active,
                    }
                    for u in users
                ]
        except Exception as e:
            logger.error(f"Error retrieving users: {str(e)}")
            return []

    def create_user_session(self, session_data: Dict) -> bool:
        """Persist a user session token hash"""
        if not self.SessionLocal:
            return False

        try:
            with self.get_session() as session:
                record = UserSessionRecord(
                    user_id=session_data.get('user_id'),
                    token_hash=session_data.get('token_hash'),
                    device_fingerprint=session_data.get('device_fingerprint'),
                    device_info=json.dumps(session_data.get('device_info', {})),
                    created_at=session_data.get('created_at') or datetime.utcnow(),
                    last_seen=session_data.get('last_seen'),
                    expires_at=session_data.get('expires_at'),
                )
                session.add(record)
            return True
        except Exception as e:
            logger.error(f"Error creating user session: {str(e)}")
            return False

    def get_session_by_token_hash(self, token_hash: str) -> Optional[Dict]:
        """Retrieve a session by token hash"""
        if not self.SessionLocal:
            return None

        try:
            with self.get_session() as session:
                record = session.query(UserSessionRecord).filter_by(token_hash=token_hash).first()
                if not record:
                    return None
                return record.to_dict()
        except Exception as e:
            logger.error(f"Error retrieving session: {str(e)}")
            return None

    def touch_session(self, token_hash: str) -> bool:
        """Update last_seen for a session"""
        if not self.SessionLocal:
            return False

        try:
            with self.get_session() as session:
                record = session.query(UserSessionRecord).filter_by(token_hash=token_hash).first()
                if not record:
                    return False
                record.last_seen = datetime.utcnow()
            return True
        except Exception as e:
            logger.error(f"Error updating session last_seen: {str(e)}")
            return False

    def get_user_sessions(self, user_id: int, include_expired: bool = False) -> List[Dict]:
        """Return sessions for a user"""
        if not self.SessionLocal:
            return []

        try:
            with self.get_session() as session:
                query = session.query(UserSessionRecord).filter_by(user_id=user_id)
                if not include_expired:
                    query = query.filter(UserSessionRecord.expires_at >= datetime.utcnow())
                records = query.order_by(UserSessionRecord.created_at.desc()).all()
                return [record.to_dict() for record in records]
        except Exception as e:
            logger.error(f"Error retrieving user sessions: {str(e)}")
            return []

    def delete_session(self, token_hash: str) -> bool:
        """Delete a session by token hash"""
        if not self.SessionLocal:
            return False

        try:
            with self.get_session() as session:
                deleted = session.query(UserSessionRecord).filter_by(token_hash=token_hash).delete()
                return deleted > 0
        except Exception as e:
            logger.error(f"Error deleting session: {str(e)}")
            return False

    def delete_user_sessions(self, user_id: int) -> int:
        """Delete all sessions for a user"""
        if not self.SessionLocal:
            return 0

        try:
            with self.get_session() as session:
                deleted = session.query(UserSessionRecord).filter_by(user_id=user_id).delete()
                return deleted
        except Exception as e:
            logger.error(f"Error deleting user sessions: {str(e)}")
            return 0

    def cleanup_expired_sessions(self) -> int:
        """Delete expired sessions"""
        if not self.SessionLocal:
            return 0

        try:
            with self.get_session() as session:
                deleted = session.query(UserSessionRecord).filter(
                    UserSessionRecord.expires_at < datetime.utcnow()
                ).delete()
                return deleted
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {str(e)}")
            return 0
    
    def delete_user(self, username: str) -> bool:
        """Delete user account (admin function)"""
        if not self.SessionLocal:
            return False
        
        try:
            with self.get_session() as session:
                user = session.query(UserRecord).filter_by(username=username).first()
                if user:
                    session.delete(user)
                    logger.info(f"User deleted: {username}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
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

                deleted_stats = session.query(TrafficStatRecord).filter(
                    TrafficStatRecord.timestamp < cutoff_date
                ).delete()

                deleted_features = session.query(TrafficFeatureRecord).filter(
                    TrafficFeatureRecord.window_start < cutoff_date
                ).delete()

                logger.info(
                    f"Cleanup: Deleted {deleted_packets} packets, {deleted_alerts} alerts, "
                    f"{deleted_stats} traffic stats, {deleted_features} traffic features"
                )
                return deleted_packets + deleted_alerts + deleted_stats + deleted_features
        
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