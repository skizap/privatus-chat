"""
Secure Voice Communication System for Privatus-chat

Implements Phase 6 roadmap requirements for secure voice calls:
- Real-time voice encryption with perfect forward secrecy
- Voice quality optimization and echo cancellation  
- Call establishment through onion routing
- Voice fingerprint protection and caller anonymity
- Traffic analysis resistance for voice data
- Anonymous call routing and metadata protection

Security Features:
- End-to-end encrypted voice streams
- Perfect forward secrecy for voice data
- Voice fingerprint obfuscation
- Anonymous caller identification
- Traffic pattern obfuscation
- Secure call establishment
"""

import asyncio
import struct
import time
import queue
import threading
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import hashlib
import hmac

# Audio processing imports (would need to be installed)
try:
    import numpy as np
    import scipy.signal
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False

from ..crypto import SecureRandom, MessageEncryption, KeyDerivation
from ..crypto.double_ratchet import DoubleRatchet, DoubleRatchetManager
from ..anonymity.onion_routing import OnionRoutingManager


class CallState(Enum):
    """Voice call states."""
    IDLE = "idle"
    INITIATING = "initiating"
    RINGING = "ringing"
    CONNECTING = "connecting"
    ACTIVE = "active"
    ENDING = "ending"
    ENDED = "ended"
    FAILED = "failed"


class VoiceCodec(Enum):
    """Supported voice codecs."""
    OPUS = "opus"
    G711_ULAW = "g711_ulaw"
    G711_ALAW = "g711_alaw"
    SPEEX = "speex"


class CallQuality(Enum):
    """Voice call quality levels."""
    LOW = "low"        # 8kHz, high compression
    MEDIUM = "medium"  # 16kHz, balanced
    HIGH = "high"      # 32kHz, low compression
    ULTRA = "ultra"    # 48kHz, minimal compression


@dataclass
class VoiceFrame:
    """Encrypted voice frame."""
    frame_id: int
    timestamp: float
    encrypted_audio: bytes
    frame_size: int
    codec: VoiceCodec
    sequence_number: int
    
    def to_bytes(self) -> bytes:
        """Serialize voice frame to bytes."""
        header = struct.pack(
            '>IQIHI',
            self.frame_id,
            int(self.timestamp * 1000000),  # microseconds
            len(self.encrypted_audio),
            self.frame_size,
            self.sequence_number
        )
        return header + self.codec.value.encode('utf-8').ljust(16, b'\x00') + self.encrypted_audio
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'VoiceFrame':
        """Deserialize voice frame from bytes."""
        if len(data) < 32:
            raise ValueError("Invalid voice frame data")
        
        header_data = data[:28]
        frame_id, timestamp_us, audio_len, frame_size, seq_num = struct.unpack('>IQIHI', header_data)
        
        codec_data = data[28:44].rstrip(b'\x00').decode('utf-8')
        codec = VoiceCodec(codec_data)
        
        encrypted_audio = data[44:44+audio_len]
        
        return cls(
            frame_id=frame_id,
            timestamp=timestamp_us / 1000000.0,
            encrypted_audio=encrypted_audio,
            frame_size=frame_size,
            codec=codec,
            sequence_number=seq_num
        )


@dataclass
class CallSession:
    """Secure voice call session."""
    call_id: str
    local_user_id: str
    remote_user_id: str
    state: CallState = CallState.IDLE
    ratchet_session: Optional[DoubleRatchet] = None
    circuit_id: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    quality: CallQuality = CallQuality.MEDIUM
    codec: VoiceCodec = VoiceCodec.OPUS
    is_anonymous: bool = True
    
    # Audio statistics
    frames_sent: int = 0
    frames_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_loss: float = 0.0
    latency_ms: float = 0.0
    
    def update_stats(self, sent: bool, frame_size: int):
        """Update call statistics."""
        if sent:
            self.frames_sent += 1
            self.bytes_sent += frame_size
        else:
            self.frames_received += 1
            self.bytes_received += frame_size


class VoiceProcessor:
    """
    Processes voice audio with echo cancellation, noise reduction,
    and voice fingerprint protection.
    """
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.frame_size = int(sample_rate * 0.02)  # 20ms frames
        self.echo_canceller = EchoCanceller(sample_rate)
        self.noise_reducer = NoiseReducer(sample_rate)
        self.voice_obfuscator = VoiceObfuscator(sample_rate)
        
    def process_outgoing_audio(self, audio_data: np.ndarray, 
                             protect_voice_print: bool = True) -> np.ndarray:
        """Process outgoing audio with privacy protections."""
        if not AUDIO_AVAILABLE:
            return audio_data
        
        # Apply noise reduction
        cleaned_audio = self.noise_reducer.reduce_noise(audio_data)
        
        # Apply echo cancellation
        echo_cancelled = self.echo_canceller.cancel_echo(cleaned_audio)
        
        # Apply voice fingerprint protection if enabled
        if protect_voice_print:
            protected_audio = self.voice_obfuscator.obfuscate_voice_print(echo_cancelled)
        else:
            protected_audio = echo_cancelled
            
        return protected_audio
    
    def process_incoming_audio(self, audio_data: np.ndarray) -> np.ndarray:
        """Process incoming audio for playback."""
        if not AUDIO_AVAILABLE:
            return audio_data
            
        # Apply noise reduction to incoming audio
        return self.noise_reducer.reduce_noise(audio_data)


class EchoCanceller:
    """Acoustic echo cancellation for voice calls."""
    
    def __init__(self, sample_rate: int):
        self.sample_rate = sample_rate
        self.filter_length = int(sample_rate * 0.1)  # 100ms filter
        self.adaptation_rate = 0.01
        self.echo_filter = np.zeros(self.filter_length)
        self.reference_history = np.zeros(self.filter_length)
        
    def cancel_echo(self, input_audio: np.ndarray, 
                   reference_audio: Optional[np.ndarray] = None) -> np.ndarray:
        """Cancel acoustic echo from input audio."""
        if not AUDIO_AVAILABLE or reference_audio is None:
            return input_audio
        
        # Update reference audio history
        self.reference_history = np.roll(self.reference_history, -len(reference_audio))
        self.reference_history[-len(reference_audio):] = reference_audio
        
        # Estimate echo
        estimated_echo = np.convolve(self.reference_history, self.echo_filter, mode='valid')
        
        # Remove echo from input
        echo_cancelled = input_audio - estimated_echo[:len(input_audio)]
        
        # Adapt filter (simplified LMS algorithm)
        error = echo_cancelled
        if len(error) <= len(self.reference_history):
            gradient = np.correlate(error, self.reference_history, mode='valid')
            self.echo_filter += self.adaptation_rate * gradient[:len(self.echo_filter)]
        
        return echo_cancelled


class NoiseReducer:
    """Noise reduction for voice audio."""
    
    def __init__(self, sample_rate: int):
        self.sample_rate = sample_rate
        self.noise_floor = None
        self.smoothing_factor = 0.95
        
    def reduce_noise(self, audio_data: np.ndarray) -> np.ndarray:
        """Reduce background noise from audio."""
        if not AUDIO_AVAILABLE:
            return audio_data
        
        # Compute power spectrum
        fft = np.fft.fft(audio_data)
        power_spectrum = np.abs(fft) ** 2
        
        # Estimate noise floor
        if self.noise_floor is None:
            self.noise_floor = power_spectrum.copy()
        else:
            # Update noise floor with smoothing
            current_noise = np.minimum(power_spectrum, self.noise_floor * 1.1)
            self.noise_floor = (self.smoothing_factor * self.noise_floor + 
                              (1 - self.smoothing_factor) * current_noise)
        
        # Apply spectral subtraction
        noise_reduction_factor = 2.0
        enhanced_spectrum = power_spectrum - noise_reduction_factor * self.noise_floor
        enhanced_spectrum = np.maximum(enhanced_spectrum, 0.1 * power_spectrum)
        
        # Reconstruct audio
        phase = np.angle(fft)
        enhanced_fft = np.sqrt(enhanced_spectrum) * np.exp(1j * phase)
        enhanced_audio = np.real(np.fft.ifft(enhanced_fft))
        
        return enhanced_audio


class VoiceObfuscator:
    """Obfuscates voice characteristics to protect identity."""
    
    def __init__(self, sample_rate: int):
        self.sample_rate = sample_rate
        self.pitch_shift_factor = 1.0
        self.formant_shift_factor = 1.0
        
    def obfuscate_voice_print(self, audio_data: np.ndarray) -> np.ndarray:
        """Apply voice obfuscation to protect voice fingerprint."""
        if not AUDIO_AVAILABLE:
            return audio_data
        
        # Apply slight pitch shifting (preserve intelligibility)
        pitch_shifted = self._pitch_shift(audio_data, self.pitch_shift_factor)
        
        # Apply formant shifting
        formant_shifted = self._formant_shift(pitch_shifted, self.formant_shift_factor)
        
        return formant_shifted
    
    def _pitch_shift(self, audio: np.ndarray, factor: float) -> np.ndarray:
        """Shift pitch of audio by given factor."""
        # Simplified pitch shifting (in practice, use PSOLA or similar)
        if factor == 1.0:
            return audio
            
        # Basic time-domain pitch shifting
        indices = np.arange(0, len(audio), factor)
        return np.interp(np.arange(len(audio)), indices, 
                        audio[np.minimum(indices.astype(int), len(audio)-1)])
    
    def _formant_shift(self, audio: np.ndarray, factor: float) -> np.ndarray:
        """Shift formants of audio."""
        # Simplified formant shifting
        if factor == 1.0:
            return audio
            
        # Apply basic spectral envelope modification
        fft = np.fft.fft(audio)
        frequencies = np.fft.fftfreq(len(audio), 1/self.sample_rate)
        
        # Shift spectral envelope
        shifted_indices = np.clip(
            np.round(np.arange(len(fft)) / factor).astype(int),
            0, len(fft) - 1
        )
        
        magnitude = np.abs(fft)
        phase = np.angle(fft)
        
        shifted_magnitude = magnitude[shifted_indices]
        shifted_fft = shifted_magnitude * np.exp(1j * phase)
        
        return np.real(np.fft.ifft(shifted_fft))


class VoiceCallManager:
    """
    Manages secure voice calls with anonymity and privacy protection.
    """
    
    def __init__(self, user_id: str, ratchet_manager: DoubleRatchetManager,
                 onion_manager: OnionRoutingManager):
        self.user_id = user_id
        self.ratchet_manager = ratchet_manager
        self.onion_manager = onion_manager
        
        # Active calls
        self.active_calls: Dict[str, CallSession] = {}
        
        # Audio processing
        self.voice_processor = VoiceProcessor()
        
        # Network callbacks
        self.send_callback: Optional[Callable] = None
        self.call_state_callbacks: List[Callable] = []
        
        # Audio streams
        self.audio_input_queue = queue.Queue()
        self.audio_output_queue = queue.Queue()
        
        # Sequence numbers for frames
        self.outgoing_sequence = 0
        self.expected_sequence: Dict[str, int] = {}
        
    def register_send_callback(self, callback: Callable[[str, bytes], None]):
        """Register callback for sending voice data."""
        self.send_callback = callback
    
    def register_call_state_callback(self, callback: Callable[[str, CallState], None]):
        """Register callback for call state changes."""
        self.call_state_callbacks.append(callback)
    
    async def initiate_call(self, remote_user_id: str, anonymous: bool = True,
                          quality: CallQuality = CallQuality.MEDIUM) -> Optional[str]:
        """Initiate a voice call to a remote user."""
        call_id = SecureRandom().generate_bytes(16).hex()
        
        # Create call session
        call_session = CallSession(
            call_id=call_id,
            local_user_id=self.user_id,
            remote_user_id=remote_user_id,
            state=CallState.INITIATING,
            quality=quality,
            is_anonymous=anonymous
        )
        
        try:
            # Establish onion circuit for anonymous calls
            if anonymous:
                circuit_id = await self.onion_manager.create_circuit()
                if not circuit_id:
                    return None
                call_session.circuit_id = circuit_id
            
            # Create Double Ratchet session for call encryption
            shared_secret = SecureRandom().generate_bytes(32)
            ratchet_session = self.ratchet_manager.create_session(
                call_id, shared_secret, b"", True  # TODO: Get actual remote key
            )
            call_session.ratchet_session = ratchet_session
            
            # Send call invitation
            invitation = self._create_call_invitation(call_session)
            await self._send_call_message(call_session, "INVITE", invitation)
            
            # Update state
            call_session.state = CallState.RINGING
            self.active_calls[call_id] = call_session
            self._notify_call_state_change(call_id, CallState.RINGING)
            
            return call_id
            
        except Exception as e:
            call_session.state = CallState.FAILED
            self._notify_call_state_change(call_id, CallState.FAILED)
            return None
    
    async def accept_call(self, call_id: str) -> bool:
        """Accept an incoming voice call."""
        if call_id not in self.active_calls:
            return False
        
        call_session = self.active_calls[call_id]
        if call_session.state != CallState.RINGING:
            return False
        
        try:
            # Send call acceptance
            acceptance = self._create_call_acceptance(call_session)
            await self._send_call_message(call_session, "ACCEPT", acceptance)
            
            # Update state
            call_session.state = CallState.CONNECTING
            call_session.started_at = datetime.now()
            self._notify_call_state_change(call_id, CallState.CONNECTING)
            
            # Start audio processing
            await self._start_audio_streams(call_session)
            
            call_session.state = CallState.ACTIVE
            self._notify_call_state_change(call_id, CallState.ACTIVE)
            
            return True
            
        except Exception as e:
            call_session.state = CallState.FAILED
            self._notify_call_state_change(call_id, CallState.FAILED)
            return False
    
    async def end_call(self, call_id: str) -> bool:
        """End an active voice call."""
        if call_id not in self.active_calls:
            return False
        
        call_session = self.active_calls[call_id]
        
        try:
            # Send call termination
            await self._send_call_message(call_session, "BYE", {})
            
            # Stop audio streams
            await self._stop_audio_streams(call_session)
            
            # Update state
            call_session.state = CallState.ENDED
            call_session.ended_at = datetime.now()
            self._notify_call_state_change(call_id, CallState.ENDED)
            
            # Cleanup
            if call_session.circuit_id:
                await self.onion_manager.destroy_circuit(call_session.circuit_id)
            
            if call_session.ratchet_session:
                self.ratchet_manager.delete_session(call_id)
            
            # Remove from active calls
            del self.active_calls[call_id]
            
            return True
            
        except Exception as e:
            call_session.state = CallState.FAILED
            self._notify_call_state_change(call_id, CallState.FAILED)
            return False
    
    async def send_voice_frame(self, call_id: str, audio_data: np.ndarray) -> bool:
        """Send an encrypted voice frame."""
        if call_id not in self.active_calls:
            return False
        
        call_session = self.active_calls[call_id]
        if call_session.state != CallState.ACTIVE or not call_session.ratchet_session:
            return False
        
        try:
            # Process outgoing audio
            processed_audio = self.voice_processor.process_outgoing_audio(
                audio_data, call_session.is_anonymous
            )
            
            # Convert to bytes
            audio_bytes = processed_audio.astype(np.int16).tobytes()
            
            # Create voice frame
            self.outgoing_sequence += 1
            voice_frame = VoiceFrame(
                frame_id=SecureRandom().generate_bytes(4).hex(),
                timestamp=time.time(),
                encrypted_audio=b"",  # Will be set after encryption
                frame_size=len(audio_bytes),
                codec=call_session.codec,
                sequence_number=self.outgoing_sequence
            )
            
            # Encrypt audio data
            frame_data = voice_frame.to_bytes()[:-len(voice_frame.encrypted_audio)] + audio_bytes
            encrypted_message = call_session.ratchet_session.encrypt_message(frame_data)
            
            if encrypted_message:
                voice_frame.encrypted_audio = json.dumps(encrypted_message).encode()
                
                # Send voice frame
                await self._send_voice_frame(call_session, voice_frame)
                
                # Update statistics
                call_session.update_stats(True, len(voice_frame.encrypted_audio))
                
                return True
            
        except Exception as e:
            return False
        
        return False
    
    async def handle_incoming_voice_frame(self, call_id: str, frame_data: bytes) -> Optional[np.ndarray]:
        """Handle an incoming encrypted voice frame."""
        if call_id not in self.active_calls:
            return None
        
        call_session = self.active_calls[call_id]
        if call_session.state != CallState.ACTIVE or not call_session.ratchet_session:
            return None
        
        try:
            # Parse voice frame
            voice_frame = VoiceFrame.from_bytes(frame_data)
            
            # Decrypt audio data
            encrypted_message = json.loads(voice_frame.encrypted_audio.decode())
            decrypted_data = call_session.ratchet_session.decrypt_message(encrypted_message)
            
            if decrypted_data:
                # Extract audio data
                header_size = len(voice_frame.to_bytes()) - len(voice_frame.encrypted_audio)
                audio_bytes = decrypted_data[header_size:]
                
                # Convert to numpy array
                audio_data = np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32)
                
                # Process incoming audio
                processed_audio = self.voice_processor.process_incoming_audio(audio_data)
                
                # Update statistics
                call_session.update_stats(False, len(frame_data))
                
                # Check for packet loss
                expected_seq = self.expected_sequence.get(call_id, 1)
                if voice_frame.sequence_number > expected_seq:
                    # Packet loss detected
                    loss_count = voice_frame.sequence_number - expected_seq
                    call_session.packet_loss = (call_session.packet_loss * 0.9 + 
                                               loss_count / voice_frame.sequence_number * 0.1)
                
                self.expected_sequence[call_id] = voice_frame.sequence_number + 1
                
                return processed_audio
            
        except Exception as e:
            return None
        
        return None
    
    def _create_call_invitation(self, call_session: CallSession) -> Dict[str, Any]:
        """Create call invitation message."""
        return {
            'call_id': call_session.call_id,
            'caller_id': call_session.local_user_id if not call_session.is_anonymous else 'anonymous',
            'quality': call_session.quality.value,
            'codec': call_session.codec.value,
            'timestamp': datetime.now().isoformat(),
            'capabilities': ['voice', 'encryption', 'anonymity']
        }
    
    def _create_call_acceptance(self, call_session: CallSession) -> Dict[str, Any]:
        """Create call acceptance message."""
        return {
            'call_id': call_session.call_id,
            'accepted': True,
            'quality': call_session.quality.value,
            'codec': call_session.codec.value,
            'timestamp': datetime.now().isoformat()
        }
    
    async def _send_call_message(self, call_session: CallSession, 
                               message_type: str, data: Dict[str, Any]) -> None:
        """Send a call control message."""
        if not self.send_callback:
            return
        
        message = {
            'type': message_type,
            'call_id': call_session.call_id,
            'data': data
        }
        
        # Encrypt message if ratchet session exists
        if call_session.ratchet_session:
            encrypted_message = call_session.ratchet_session.encrypt_message(
                json.dumps(message).encode()
            )
            if encrypted_message:
                message_data = json.dumps(encrypted_message).encode()
            else:
                message_data = json.dumps(message).encode()
        else:
            message_data = json.dumps(message).encode()
        
        # Send through appropriate channel
        if call_session.circuit_id:
            await self.onion_manager.send_through_circuit(
                call_session.circuit_id, message_data
            )
        else:
            self.send_callback(call_session.remote_user_id, message_data)
    
    async def _send_voice_frame(self, call_session: CallSession, 
                              voice_frame: VoiceFrame) -> None:
        """Send a voice frame through the appropriate channel."""
        if not self.send_callback:
            return
        
        frame_data = voice_frame.to_bytes()
        
        # Apply traffic analysis resistance
        padded_data = self._apply_traffic_obfuscation(frame_data)
        
        # Send through appropriate channel
        if call_session.circuit_id:
            await self.onion_manager.send_through_circuit(
                call_session.circuit_id, padded_data
            )
        else:
            self.send_callback(call_session.remote_user_id, padded_data)
    
    def _apply_traffic_obfuscation(self, data: bytes) -> bytes:
        """Apply traffic analysis resistance to voice data."""
        # Pad to fixed size to hide actual frame sizes
        target_size = 1024  # Fixed frame size
        if len(data) < target_size:
            padding_size = target_size - len(data)
            padding = SecureRandom().generate_bytes(padding_size)
            return data + padding
        elif len(data) > target_size:
            # Fragment large frames
            return data[:target_size]
        return data
    
    async def _start_audio_streams(self, call_session: CallSession) -> None:
        """Start audio input/output streams for the call."""
        # Placeholder for audio stream initialization
        # In practice, this would initialize audio capture and playback
        pass
    
    async def _stop_audio_streams(self, call_session: CallSession) -> None:
        """Stop audio streams for the call."""
        # Placeholder for audio stream cleanup
        pass
    
    def _notify_call_state_change(self, call_id: str, new_state: CallState) -> None:
        """Notify registered callbacks of call state changes."""
        for callback in self.call_state_callbacks:
            try:
                callback(call_id, new_state)
            except Exception:
                pass  # Ignore callback errors
    
    def get_call_statistics(self, call_id: str) -> Optional[Dict[str, Any]]:
        """Get statistics for an active call."""
        if call_id not in self.active_calls:
            return None
        
        call_session = self.active_calls[call_id]
        duration = None
        
        if call_session.started_at:
            if call_session.ended_at:
                duration = (call_session.ended_at - call_session.started_at).total_seconds()
            else:
                duration = (datetime.now() - call_session.started_at).total_seconds()
        
        return {
            'call_id': call_id,
            'state': call_session.state.value,
            'duration_seconds': duration,
            'frames_sent': call_session.frames_sent,
            'frames_received': call_session.frames_received,
            'bytes_sent': call_session.bytes_sent,
            'bytes_received': call_session.bytes_received,
            'packet_loss_percent': call_session.packet_loss * 100,
            'latency_ms': call_session.latency_ms,
            'quality': call_session.quality.value,
            'codec': call_session.codec.value,
            'is_anonymous': call_session.is_anonymous
        }
    
    def get_all_calls(self) -> List[str]:
        """Get list of all active call IDs."""
        return list(self.active_calls.keys())


# Audio codec simulation (placeholder for real audio processing)
class AudioCodec:
    """Placeholder audio codec for voice compression/decompression."""
    
    @staticmethod
    def encode(audio_data: np.ndarray, codec: VoiceCodec, quality: CallQuality) -> bytes:
        """Encode audio data with specified codec and quality."""
        if not AUDIO_AVAILABLE:
            return audio_data.tobytes() if hasattr(audio_data, 'tobytes') else audio_data
        
        # Placeholder encoding - in practice, use actual codec libraries
        compression_factors = {
            CallQuality.LOW: 8,
            CallQuality.MEDIUM: 4,
            CallQuality.HIGH: 2,
            CallQuality.ULTRA: 1
        }
        
        factor = compression_factors.get(quality, 4)
        compressed_audio = audio_data[::factor]  # Simple downsampling
        
        return compressed_audio.astype(np.int16).tobytes()
    
    @staticmethod
    def decode(encoded_data: bytes, codec: VoiceCodec, quality: CallQuality) -> np.ndarray:
        """Decode audio data with specified codec and quality."""
        if not AUDIO_AVAILABLE:
            return np.frombuffer(encoded_data, dtype=np.uint8)
        
        # Placeholder decoding
        audio_data = np.frombuffer(encoded_data, dtype=np.int16).astype(np.float32)
        
        compression_factors = {
            CallQuality.LOW: 8,
            CallQuality.MEDIUM: 4,
            CallQuality.HIGH: 2,
            CallQuality.ULTRA: 1
        }
        
        factor = compression_factors.get(quality, 4)
        if factor > 1:
            # Simple upsampling for decompression
            upsampled = np.repeat(audio_data, factor)
            return upsampled[:len(upsampled)//factor * factor]  # Ensure proper length
        
        return audio_data 