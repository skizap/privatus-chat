"""
GUI Responsiveness Optimizer

Optimizes GUI performance for large contact lists and message histories including:
- Virtual scrolling for large lists
- Lazy loading of message histories
- Efficient contact list management
- Background loading and caching
- UI thread optimization
"""

import asyncio
import time
import logging
import threading
from typing import Dict, List, Optional, Any, Callable, Tuple
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
import weakref

logger = logging.getLogger(__name__)


class LoadingStrategy(Enum):
    """Loading strategies for GUI components"""
    LAZY = "lazy"              # Load on demand
    VIRTUAL = "virtual"        # Virtual scrolling
    PAGINATED = "paginated"    # Load in pages
    BACKGROUND = "background"  # Load in background
    HYBRID = "hybrid"         # Combination of strategies


@dataclass
class VirtualScrollItem:
    """Represents an item in a virtual scrolling list"""
    item_id: str
    data: Any
    height: int
    index: int
    is_loaded: bool = False
    is_visible: bool = False
    last_accessed: float = field(default_factory=time.time)


class VirtualScrollManager:
    """Manages virtual scrolling for large lists"""

    def __init__(self, container_height: int = 600, item_height: int = 50,
                 buffer_size: int = 100):
        self.container_height = container_height
        self.item_height = item_height
        self.buffer_size = buffer_size

        # Virtual scrolling state
        self.items: Dict[str, VirtualScrollItem] = {}
        self.visible_items: Set[str] = set()
        self.loaded_items: Set[str] = set()

        # Scroll position tracking
        self.scroll_position = 0
        self.total_height = 0

        # Loading state
        self.loading_queue: asyncio.Queue = asyncio.Queue()
        self.loading_task: Optional[asyncio.Task] = None

        # Thread safety
        self._lock = threading.RLock()

    async def start(self):
        """Start the virtual scroll manager"""
        if self.loading_task is None:
            self.loading_task = asyncio.create_task(self._loading_loop())

    async def stop(self):
        """Stop the virtual scroll manager"""
        if self.loading_task:
            self.loading_task.cancel()
            self.loading_task = None

    def add_items(self, items: List[Tuple[str, Any]]):
        """Add items to the virtual list"""
        with self._lock:
            start_index = len(self.items)
            for i, (item_id, data) in enumerate(items):
                item = VirtualScrollItem(
                    item_id=item_id,
                    data=data,
                    height=self.item_height,
                    index=start_index + i
                )
                self.items[item_id] = item

            self._update_total_height()

    def update_scroll_position(self, position: int):
        """Update scroll position and calculate visible items"""
        with self._lock:
            self.scroll_position = position
            self._calculate_visible_items()

    def _calculate_visible_items(self):
        """Calculate which items are currently visible"""
        start_index = max(0, self.scroll_position // self.item_height - self.buffer_size)
        end_index = min(
            len(self.items),
            (self.scroll_position + self.container_height) // self.item_height + self.buffer_size
        )

        # Update visibility
        current_visible = set()
        for item in self.items.values():
            item.is_visible = start_index <= item.index <= end_index
            if item.is_visible:
                current_visible.add(item.item_id)

        # Queue loading for newly visible items
        newly_visible = current_visible - self.visible_items
        for item_id in newly_visible:
            if item_id in self.items:
                asyncio.create_task(self._queue_item_loading(item_id))

        self.visible_items = current_visible

    async def _queue_item_loading(self, item_id: str):
        """Queue an item for loading"""
        await self.loading_queue.put(item_id)

    async def _loading_loop(self):
        """Background loading loop"""
        while True:
            try:
                item_id = await asyncio.wait_for(self.loading_queue.get(), timeout=1.0)

                if item_id in self.items:
                    await self._load_item_data(item_id)
                    self.items[item_id].is_loaded = True
                    self.loaded_items.add(item_id)

                self.loading_queue.task_done()

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in loading loop: {e}")

    async def _load_item_data(self, item_id: str):
        """Load data for an item (would implement actual loading logic)"""
        # This would implement actual data loading
        # For now, just simulate async loading
        await asyncio.sleep(0.01)

    def _update_total_height(self):
        """Update total height of the virtual list"""
        self.total_height = len(self.items) * self.item_height

    def get_visible_items_data(self) -> List[Tuple[str, Any, int]]:
        """Get data for currently visible items"""
        with self._lock:
            visible_data = []
            for item_id in self.visible_items:
                if item_id in self.items:
                    item = self.items[item_id]
                    if item.is_loaded:
                        visible_data.append((item_id, item.data, item.index * self.item_height))

            return visible_data

    def get_scroll_info(self) -> Dict[str, Any]:
        """Get scroll information"""
        with self._lock:
            return {
                'scroll_position': self.scroll_position,
                'total_height': self.total_height,
                'container_height': self.container_height,
                'visible_items': len(self.visible_items),
                'loaded_items': len(self.loaded_items),
                'total_items': len(self.items)
            }


class LazyMessageLoader:
    """Lazy loading for message histories"""

    def __init__(self, messages_per_page: int = 50, max_cache_pages: int = 10):
        self.messages_per_page = messages_per_page
        self.max_cache_pages = max_cache_pages

        # Message storage
        self.message_pages: Dict[int, List[Dict[str, Any]]] = {}
        self.loaded_pages: Set[int] = set()

        # Loading state
        self.loading_pages: Set[int] = set()
        self.total_pages = 0
        self.total_messages = 0

        # Cache management
        self.page_access_times: Dict[int, float] = {}
        self.access_order: deque = deque()

        # Thread safety
        self._lock = threading.RLock()

    async def load_message_page(self, page_index: int, contact_id: str) -> List[Dict[str, Any]]:
        """Load a page of messages"""
        with self._lock:
            if page_index in self.loaded_pages:
                # Update access tracking
                self.page_access_times[page_index] = time.time()
                self._update_access_order(page_index)
                return self.message_pages[page_index]

            if page_index in self.loading_pages:
                # Already loading, wait for it
                while page_index in self.loading_pages:
                    await asyncio.sleep(0.01)
                return self.message_pages.get(page_index, [])

        # Load the page
        try:
            messages = await self._load_messages_from_storage(contact_id, page_index)

            with self._lock:
                self.message_pages[page_index] = messages
                self.loaded_pages.add(page_index)
                self.loading_pages.discard(page_index)

                # Update access tracking
                self.page_access_times[page_index] = time.time()
                self._update_access_order(page_index)

                # Manage cache size
                self._manage_cache_size()

            return messages

        except Exception as e:
            logger.error(f"Failed to load message page {page_index}: {e}")
            with self._lock:
                self.loading_pages.discard(page_index)
            return []

    async def _load_messages_from_storage(self, contact_id: str, page_index: int) -> List[Dict[str, Any]]:
        """Load messages from storage (would implement actual storage call)"""
        # This would implement actual message loading from storage
        # For now, return empty list
        await asyncio.sleep(0.05)  # Simulate loading time
        return []

    def _update_access_order(self, page_index: int):
        """Update access order for LRU cache"""
        if page_index in self.access_order:
            self.access_order.remove(page_index)
        self.access_order.append(page_index)

        # Keep only recent pages
        if len(self.access_order) > self.max_cache_pages:
            oldest_page = self.access_order.popleft()
            self._evict_page(oldest_page)

    def _manage_cache_size(self):
        """Manage cache size by evicting old pages"""
        while len(self.loaded_pages) > self.max_cache_pages:
            if self.access_order:
                oldest_page = self.access_order.popleft()
                self._evict_page(oldest_page)

    def _evict_page(self, page_index: int):
        """Evict a page from cache"""
        if page_index in self.message_pages:
            del self.message_pages[page_index]
            self.loaded_pages.discard(page_index)
            if page_index in self.page_access_times:
                del self.page_access_times[page_index]

    def get_page_info(self, page_index: int) -> Optional[Dict[str, Any]]:
        """Get information about a page"""
        with self._lock:
            if page_index in self.message_pages:
                return {
                    'loaded': True,
                    'message_count': len(self.message_pages[page_index]),
                    'last_accessed': self.page_access_times.get(page_index, 0)
                }
            elif page_index in self.loading_pages:
                return {
                    'loaded': False,
                    'loading': True
                }
            else:
                return {
                    'loaded': False,
                    'loading': False
                }

    def get_loading_stats(self) -> Dict[str, Any]:
        """Get loading statistics"""
        with self._lock:
            return {
                'loaded_pages': len(self.loaded_pages),
                'loading_pages': len(self.loading_pages),
                'total_pages': self.total_pages,
                'cache_size': len(self.message_pages),
                'max_cache_pages': self.max_cache_pages
            }


class ContactListOptimizer:
    """Optimizes contact list performance"""

    def __init__(self, batch_size: int = 100, search_debounce_ms: int = 300):
        self.batch_size = batch_size
        self.search_debounce_ms = search_debounce_ms

        # Contact data
        self.contacts: Dict[str, Dict[str, Any]] = {}
        self.filtered_contacts: List[str] = []
        self.contact_batches: Dict[int, List[str]] = defaultdict(list)

        # Search and filtering
        self.search_timer: Optional[asyncio.Task] = None
        self.current_search = ""
        self.search_index: Dict[str, List[str]] = defaultdict(list)

        # Performance tracking
        self.filter_times: deque = deque(maxlen=100)
        self.render_times: deque = deque(maxlen=100)

        # Thread safety
        self._lock = threading.RLock()

    def add_contacts(self, contacts: List[Dict[str, Any]]):
        """Add contacts to the list"""
        with self._lock:
            for contact in contacts:
                contact_id = contact['id']
                self.contacts[contact_id] = contact

                # Add to search index
                self._add_to_search_index(contact)

            self._rebuild_batches()

    def _add_to_search_index(self, contact: Dict[str, Any]):
        """Add contact to search index"""
        contact_id = contact['id']
        searchable_text = f"{contact.get('name', '')} {contact.get('id', '')}".lower()

        # Add to each word index
        for word in searchable_text.split():
            self.search_index[word].append(contact_id)

    def _rebuild_batches(self):
        """Rebuild contact batches for efficient loading"""
        contact_ids = list(self.contacts.keys())
        for i in range(0, len(contact_ids), self.batch_size):
            batch_index = i // self.batch_size
            batch_contacts = contact_ids[i:i + self.batch_size]
            self.contact_batches[batch_index] = batch_contacts

    async def search_contacts(self, query: str):
        """Search contacts with debouncing"""
        # Cancel previous search
        if self.search_timer:
            self.search_timer.cancel()

        # Start new search after debounce delay
        self.search_timer = asyncio.create_task(self._delayed_search(query))

    async def _delayed_search(self, query: str):
        """Delayed search execution"""
        await asyncio.sleep(self.search_debounce_ms / 1000.0)

        start_time = time.time()
        await self._execute_search(query)
        search_time = time.time() - start_time

        with self._lock:
            self.filter_times.append(search_time)

    async def _execute_search(self, query: str):
        """Execute the actual search"""
        with self._lock:
            self.current_search = query.lower()

            if not query:
                self.filtered_contacts = list(self.contacts.keys())
            else:
                # Find matching contacts
                matching_ids = set()
                query_words = query.split()

                for word in query_words:
                    if word in self.search_index:
                        if not matching_ids:
                            matching_ids = set(self.search_index[word])
                        else:
                            matching_ids = matching_ids.intersection(set(self.search_index[word]))

                self.filtered_contacts = list(matching_ids)

    def get_batch(self, batch_index: int) -> List[Dict[str, Any]]:
        """Get a batch of contacts"""
        with self._lock:
            contact_ids = self.contact_batches.get(batch_index, [])
            return [self.contacts[cid] for cid in contact_ids if cid in self.contacts]

    def get_filtered_batch(self, start_index: int, count: int) -> List[Dict[str, Any]]:
        """Get filtered contacts for virtual scrolling"""
        with self._lock:
            end_index = min(start_index + count, len(self.filtered_contacts))
            batch_ids = self.filtered_contacts[start_index:end_index]
            return [self.contacts[cid] for cid in batch_ids if cid in self.contacts]

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        with self._lock:
            avg_filter_time = sum(self.filter_times) / max(1, len(self.filter_times))
            avg_render_time = sum(self.render_times) / max(1, len(self.render_times))

            return {
                'total_contacts': len(self.contacts),
                'filtered_contacts': len(self.filtered_contacts),
                'batches': len(self.contact_batches),
                'search_terms': len(self.search_index),
                'avg_filter_time': avg_filter_time,
                'avg_render_time': avg_render_time,
                'current_search': self.current_search
            }


class BackgroundLoader:
    """Background loader for GUI data"""

    def __init__(self, max_concurrent_loads: int = 5):
        self.max_concurrent_loads = max_concurrent_loads

        # Loading queues
        self.contact_queue: asyncio.Queue = asyncio.Queue()
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.file_queue: asyncio.Queue = asyncio.Queue()

        # Loading workers
        self.workers: List[asyncio.Task] = []
        self.running = False

        # Statistics
        self.loads_completed = 0
        self.loads_failed = 0
        self.average_load_time = 0.0

    async def start(self):
        """Start the background loader"""
        if self.running:
            return

        self.running = True

        # Start workers
        for i in range(self.max_concurrent_loads):
            worker = asyncio.create_task(self._loading_worker(i))
            self.workers.append(worker)

        logger.info(f"Background loader started with {self.max_concurrent_loads} workers")

    async def stop(self):
        """Stop the background loader"""
        if not self.running:
            return

        self.running = False

        # Cancel workers
        for worker in self.workers:
            worker.cancel()

        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)

        logger.info("Background loader stopped")

    async def queue_contact_load(self, contact_id: str, priority: int = 0):
        """Queue contact loading"""
        await self.contact_queue.put((priority, contact_id))

    async def queue_message_load(self, contact_id: str, page: int, priority: int = 0):
        """Queue message page loading"""
        await self.message_queue.put((priority, contact_id, page))

    async def _loading_worker(self, worker_id: int):
        """Background loading worker"""
        logger.debug(f"Loading worker {worker_id} started")

        while self.running:
            try:
                # Check all queues for work
                work_item = await self._get_next_work_item()

                if work_item:
                    start_time = time.time()
                    success = await self._process_work_item(work_item)
                    load_time = time.time() - start_time

                    with self._lock:
                        if success:
                            self.loads_completed += 1
                        else:
                            self.loads_failed += 1
                        self.average_load_time = (
                            (self.average_load_time * 0.9) + (load_time * 0.1)
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Loading worker {worker_id} error: {e}")

        logger.debug(f"Loading worker {worker_id} stopped")

    async def _get_next_work_item(self) -> Optional[Tuple]:
        """Get next work item from any queue"""
        # Try contact queue first
        try:
            item = self.contact_queue.get_nowait()
            self.contact_queue.task_done()
            return ('contact',) + item
        except asyncio.QueueEmpty:
            pass

        # Try message queue
        try:
            item = self.message_queue.get_nowait()
            self.message_queue.task_done()
            return ('message',) + item
        except asyncio.QueueEmpty:
            pass

        # Wait for any queue to have work
        done, pending = await asyncio.wait([
            self.contact_queue.get(),
            self.message_queue.get()
        ], return_when=asyncio.FIRST_COMPLETED)

        for task in done:
            if task == pending[0]:  # Contact queue
                item = task.result()
                self.contact_queue.task_done()
                return ('contact',) + item
            else:  # Message queue
                item = task.result()
                self.message_queue.task_done()
                return ('message',) + item

        return None

    async def _process_work_item(self, work_item: Tuple) -> bool:
        """Process a work item"""
        work_type = work_item[0]

        try:
            if work_type == 'contact':
                priority, contact_id = work_item[1:]
                return await self._load_contact_data(contact_id)
            elif work_type == 'message':
                priority, contact_id, page = work_item[1:]
                return await self._load_message_page(contact_id, page)

            return False

        except Exception as e:
            logger.error(f"Failed to process work item {work_item}: {e}")
            return False

    async def _load_contact_data(self, contact_id: str) -> bool:
        """Load contact data (would implement actual loading)"""
        await asyncio.sleep(0.02)  # Simulate loading
        return True

    async def _load_message_page(self, contact_id: str, page: int) -> bool:
        """Load message page (would implement actual loading)"""
        await asyncio.sleep(0.05)  # Simulate loading
        return True

    def get_loading_stats(self) -> Dict[str, Any]:
        """Get loading statistics"""
        return {
            'loads_completed': self.loads_completed,
            'loads_failed': self.loads_failed,
            'average_load_time': self.average_load_time,
            'contact_queue_size': self.contact_queue.qsize(),
            'message_queue_size': self.message_queue.qsize(),
            'workers': len(self.workers)
        }


class GUIResponsivenessOptimizer:
    """Main GUI responsiveness optimizer"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}

        # Initialize components
        self.virtual_scroll = VirtualScrollManager(
            container_height=config.get('container_height', 600),
            item_height=config.get('item_height', 50),
            buffer_size=config.get('buffer_size', 100)
        )

        self.message_loader = LazyMessageLoader(
            messages_per_page=config.get('messages_per_page', 50),
            max_cache_pages=config.get('max_cache_pages', 10)
        )

        self.contact_optimizer = ContactListOptimizer(
            batch_size=config.get('contact_batch_size', 100),
            search_debounce_ms=config.get('search_debounce_ms', 300)
        )

        self.background_loader = BackgroundLoader(
            max_concurrent_loads=config.get('max_concurrent_loads', 5)
        )

        # Configuration
        self.loading_strategy = LoadingStrategy(config.get('loading_strategy', 'HYBRID'))
        self.enable_background_loading = config.get('enable_background_loading', True)

        # State
        self.running = False

    async def start(self):
        """Start the GUI responsiveness optimizer"""
        if self.running:
            return

        self.running = True

        # Start components
        await self.virtual_scroll.start()
        await self.background_loader.start()

        logger.info("GUI responsiveness optimizer started")

    async def stop(self):
        """Stop the GUI responsiveness optimizer"""
        if not self.running:
            return

        self.running = False

        # Stop components
        await self.background_loader.stop()
        await self.virtual_scroll.stop()

        logger.info("GUI responsiveness optimizer stopped")

    def add_contacts(self, contacts: List[Dict[str, Any]]):
        """Add contacts for optimization"""
        self.contact_optimizer.add_contacts(contacts)

    async def search_contacts(self, query: str):
        """Search contacts with optimization"""
        await self.contact_optimizer.search_contacts(query)

    def get_contacts_batch(self, batch_index: int) -> List[Dict[str, Any]]:
        """Get a batch of contacts"""
        return self.contact_optimizer.get_batch(batch_index)

    def get_filtered_contacts_batch(self, start_index: int, count: int) -> List[Dict[str, Any]]:
        """Get filtered contacts for virtual scrolling"""
        return self.contact_optimizer.get_filtered_batch(start_index, count)

    async def load_message_page(self, page_index: int, contact_id: str) -> List[Dict[str, Any]]:
        """Load a page of messages"""
        return await self.message_loader.load_message_page(page_index, contact_id)

    def update_scroll_position(self, position: int):
        """Update virtual scroll position"""
        self.virtual_scroll.update_scroll_position(position)

    def get_visible_items(self) -> List[Tuple[str, Any, int]]:
        """Get currently visible items"""
        return self.virtual_scroll.get_visible_items_data()

    def get_scroll_info(self) -> Dict[str, Any]:
        """Get scroll information"""
        return self.virtual_scroll.get_scroll_info()

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics"""
        return {
            'virtual_scroll': self.virtual_scroll.get_scroll_info(),
            'message_loader': self.message_loader.get_loading_stats(),
            'contact_optimizer': self.contact_optimizer.get_performance_stats(),
            'background_loader': self.background_loader.get_loading_stats(),
            'configuration': {
                'loading_strategy': self.loading_strategy.value,
                'enable_background_loading': self.enable_background_loading
            }
        }