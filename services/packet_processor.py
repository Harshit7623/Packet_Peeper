"""
Async Packet Processing Pipeline
Decouples packet capture from analysis for better performance
Uses threading-based queue for processor parallelization
"""

import queue
import threading
import logging
from typing import Callable, Optional, Dict
from datetime import datetime
from config.config import PACKET_QUEUE_SIZE, WORKER_THREADS, ASYNC_PROCESSING

logger = logging.getLogger(__name__)

class PacketProcessor:
    """
    Multi-threaded packet processing pipeline.
    Producers (packet capture) put packets in queue,
    Consumers (analyzers) process them asynchronously.
    """
    
    def __init__(self, num_workers: int = WORKER_THREADS, queue_size: int = PACKET_QUEUE_SIZE):
        """
        Initialize the processor with worker threads.
        
        Args:
            num_workers: Number of worker threads to spawn
            queue_size: Maximum size of the processing queue
        """
        self.queue = queue.Queue(maxsize=queue_size)
        self.num_workers = num_workers
        self.workers = []
        self.running = False
        self.callbacks = []
        self.error_count = 0
        self.processed_count = 0
        
        logger.info(f"🔄 PacketProcessor initialized with {num_workers} workers, queue size {queue_size}")
    
    def register_callback(self, callback: Callable[[Dict], None]) -> None:
        """Register a callback to be called for each processed packet"""
        self.callbacks.append(callback)
        logger.info(f"📌 Registered callback: {callback.__name__}")
    
    def start(self) -> None:
        """Start worker threads"""
        if self.running:
            logger.warning("⚠️  Processor already running")
            return
        
        self.running = True
        
        # Start worker threads
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(i,),
                daemon=True,
                name=f"PacketWorker-{i}"
            )
            worker.start()
            self.workers.append(worker)
        
        logger.info(f"✅ Started {self.num_workers} worker threads")
    
    def stop(self) -> None:
        """Stop all worker threads gracefully"""
        self.running = False
        
        # Send stop signals
        for _ in range(self.num_workers):
            try:
                self.queue.put(None, timeout=1)
            except queue.Full:
                pass
        
        # Wait for threads to finish
        for worker in self.workers:
            worker.join(timeout=5)
        
        self.workers.clear()
        logger.info(f"⛔ Processor stopped. Processed: {self.processed_count}, Errors: {self.error_count}")
    
    def put_packet(self, packet_info: Dict) -> bool:
        """
        Add a packet to the processing queue.
        
        Args:
            packet_info: Packet metadata dictionary
            
        Returns:
            True if packet was queued, False if queue is full
        """
        if not self.running:
            return False
        
        try:
            self.queue.put(packet_info, block=False)
            return True
        except queue.Full:
            logger.debug("📤 Packet queue full, dropping packet")
            self.error_count += 1
            return False
    
    def _worker_loop(self, worker_id: int) -> None:
        """
        Main worker loop. Continuously processes packets from queue.
        
        Args:
            worker_id: Worker thread identifier
        """
        logger.info(f"👷 Worker {worker_id} started")
        
        while self.running:
            try:
                # Get packet with timeout to allow graceful shutdown
                packet_info = self.queue.get(timeout=1)
                
                # Stop signal (None)
                if packet_info is None:
                    break
                
                # Process the packet
                self._process_packet(packet_info, worker_id)
                self.processed_count += 1
                
            except queue.Empty:
                # Timeout; continue to check self.running
                continue
            except Exception as e:
                logger.error(f"👷 Worker {worker_id} error: {str(e)}")
                self.error_count += 1
        
        logger.info(f"👷 Worker {worker_id} stopped")
    
    def _process_packet(self, packet_info: Dict, worker_id: int) -> None:
        """
        Process a single packet through all registered callbacks.
        
        Args:
            packet_info: Packet metadata
            worker_id: Worker thread ID (for logging)
        """
        try:
            # Enrich packet info if needed
            if 'timestamp_epoch' not in packet_info:
                packet_info['timestamp_epoch'] = datetime.now().timestamp()
            
            # Call all registered callbacks
            for callback in self.callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    logger.error(f"📌 Callback {callback.__name__} failed: {str(e)}")
        
        except Exception as e:
            logger.error(f"👷 Worker {worker_id} processing error: {str(e)}")
            self.error_count += 1
    
    def get_stats(self) -> Dict:
        """Get processor statistics"""
        return {
            'running': self.running,
            'num_workers': self.num_workers,
            'queue_size': self.queue.qsize(),
            'queue_max': self.queue.maxsize,
            'processed': self.processed_count,
            'errors': self.error_count,
        }

# ============== SINGLETON INSTANCE ==============
_processor = None

def get_packet_processor() -> PacketProcessor:
    """Get or create singleton packet processor"""
    global _processor
    if _processor is None:
        _processor = PacketProcessor(num_workers=WORKER_THREADS)
    return _processor

def init_packet_processor() -> PacketProcessor:
    """Initialize and start the packet processor"""
    processor = get_packet_processor()
    if not processor.running and ASYNC_PROCESSING:
        processor.start()
    return processor