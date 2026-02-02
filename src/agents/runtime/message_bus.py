"""
Agent Message Bus
Async message passing system for inter-agent communication.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional
from uuid import UUID, uuid4
import structlog

logger = structlog.get_logger(__name__)


class MessageType(Enum):
    """Types of messages agents can send."""

    # Threat lifecycle
    THREAT_DETECTED = "threat_detected"
    THREAT_ANALYZED = "threat_analyzed"
    RESPONSE_PLANNED = "response_planned"
    ACTION_EXECUTED = "action_executed"
    THREAT_MITIGATED = "threat_mitigated"

    # Agent coordination
    AGENT_REQUEST = "agent_request"
    AGENT_RESPONSE = "agent_response"
    AGENT_BROADCAST = "agent_broadcast"

    # System events
    SYSTEM_ALERT = "system_alert"
    HEALTH_CHECK = "health_check"
    SHUTDOWN = "shutdown"


@dataclass
class AgentMessage:
    """Message passed between agents."""

    id: UUID
    type: MessageType
    sender: str
    payload: dict
    timestamp: datetime = field(default_factory=datetime.utcnow)
    target: Optional[str] = None  # None means broadcast
    correlation_id: Optional[UUID] = None  # Link related messages
    priority: int = 5  # 1 = highest, 10 = lowest

    @classmethod
    def create(
        cls,
        type: MessageType,
        sender: str,
        payload: dict,
        target: Optional[str] = None,
        correlation_id: Optional[UUID] = None,
        priority: int = 5,
    ) -> "AgentMessage":
        """Create a new message."""
        return cls(
            id=uuid4(),
            type=type,
            sender=sender,
            payload=payload,
            target=target,
            correlation_id=correlation_id,
            priority=priority,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "type": self.type.value,
            "sender": self.sender,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "target": self.target,
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "priority": self.priority,
        }


class MessageBus:
    """
    Async message bus for agent communication.

    Supports:
    - Pub/sub pattern for broadcast messages
    - Point-to-point messaging for targeted communication
    - Priority queues for message ordering
    - Async handlers with concurrent processing
    """

    def __init__(self, max_queue_size: int = 1000):
        self._subscribers: dict[str, dict[MessageType, list[Callable]]] = {}
        self._queues: dict[str, asyncio.PriorityQueue] = {}
        self._running = False
        self._processors: dict[str, asyncio.Task] = {}
        self._max_queue_size = max_queue_size
        self._message_count = 0
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the message bus."""
        self._running = True
        logger.info("message_bus_started")

    async def stop(self) -> None:
        """Stop the message bus and all processors."""
        self._running = False

        # Cancel all processor tasks
        for agent_id, task in self._processors.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self._processors.clear()
        logger.info("message_bus_stopped")

    def register_agent(
        self,
        agent_id: str,
        message_types: list[MessageType],
        handler: Callable[[AgentMessage], Any],
    ) -> None:
        """
        Register an agent with the message bus.

        Args:
            agent_id: Unique agent identifier
            message_types: Message types this agent handles
            handler: Async callback for handling messages
        """
        if agent_id not in self._subscribers:
            self._subscribers[agent_id] = {}
            self._queues[agent_id] = asyncio.PriorityQueue(
                maxsize=self._max_queue_size
            )

        for msg_type in message_types:
            if msg_type not in self._subscribers[agent_id]:
                self._subscribers[agent_id][msg_type] = []
            self._subscribers[agent_id][msg_type].append(handler)

        logger.info(
            "agent_registered",
            agent_id=agent_id,
            message_types=[mt.value for mt in message_types],
        )

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent from the message bus."""
        if agent_id in self._subscribers:
            del self._subscribers[agent_id]
        if agent_id in self._queues:
            del self._queues[agent_id]
        if agent_id in self._processors:
            self._processors[agent_id].cancel()
            del self._processors[agent_id]

        logger.info("agent_unregistered", agent_id=agent_id)

    async def publish(self, message: AgentMessage) -> None:
        """
        Publish a message to the bus.

        Messages are delivered based on:
        - target: If specified, only that agent receives it
        - type: All agents subscribed to that type receive it
        """
        async with self._lock:
            self._message_count += 1

        if message.target:
            # Point-to-point: deliver to specific agent
            await self._deliver_to_agent(message.target, message)
        else:
            # Broadcast: deliver to all subscribers of this type
            await self._broadcast(message)

        logger.debug(
            "message_published",
            message_id=str(message.id),
            type=message.type.value,
            sender=message.sender,
            target=message.target,
        )

    async def _deliver_to_agent(self, agent_id: str, message: AgentMessage) -> None:
        """Deliver message to a specific agent."""
        if agent_id in self._queues:
            # Priority queue uses (priority, timestamp, message) for ordering
            await self._queues[agent_id].put(
                (message.priority, message.timestamp.timestamp(), message)
            )

    async def _broadcast(self, message: AgentMessage) -> None:
        """Broadcast message to all interested agents."""
        tasks = []
        for agent_id, subscriptions in self._subscribers.items():
            if message.type in subscriptions and agent_id != message.sender:
                tasks.append(self._deliver_to_agent(agent_id, message))

        if tasks:
            await asyncio.gather(*tasks)

    async def start_processor(self, agent_id: str) -> None:
        """Start message processor for an agent."""
        if agent_id not in self._queues:
            raise ValueError(f"Agent {agent_id} not registered")

        if agent_id in self._processors:
            return  # Already running

        task = asyncio.create_task(self._process_messages(agent_id))
        self._processors[agent_id] = task

        logger.info("processor_started", agent_id=agent_id)

    async def _process_messages(self, agent_id: str) -> None:
        """Process messages for an agent."""
        queue = self._queues[agent_id]

        while self._running:
            try:
                # Wait for message with timeout to check running state
                try:
                    priority, timestamp, message = await asyncio.wait_for(
                        queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                # Find handlers for this message type
                handlers = self._subscribers.get(agent_id, {}).get(message.type, [])

                # Execute handlers concurrently
                if handlers:
                    tasks = [handler(message) for handler in handlers]
                    await asyncio.gather(*tasks, return_exceptions=True)

                queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "message_processing_error",
                    agent_id=agent_id,
                    error=str(e),
                )

    async def request_response(
        self,
        target: str,
        message: AgentMessage,
        timeout: float = 30.0,
    ) -> Optional[AgentMessage]:
        """
        Send a request and wait for response.

        Args:
            target: Target agent ID
            message: Request message
            timeout: Response timeout in seconds

        Returns:
            Response message or None if timeout
        """
        response_event = asyncio.Event()
        response_holder: list[AgentMessage] = []

        # Register temporary handler for response
        def response_handler(msg: AgentMessage) -> None:
            if msg.correlation_id == message.id:
                response_holder.append(msg)
                response_event.set()

        # Add correlation tracking
        message.target = target

        # Send request
        await self.publish(message)

        # Wait for response
        try:
            await asyncio.wait_for(response_event.wait(), timeout=timeout)
            return response_holder[0] if response_holder else None
        except asyncio.TimeoutError:
            logger.warning(
                "request_timeout",
                message_id=str(message.id),
                target=target,
            )
            return None

    def get_stats(self) -> dict:
        """Get message bus statistics."""
        return {
            "total_messages": self._message_count,
            "registered_agents": list(self._subscribers.keys()),
            "active_processors": list(self._processors.keys()),
            "queue_sizes": {
                agent_id: queue.qsize()
                for agent_id, queue in self._queues.items()
            },
        }
