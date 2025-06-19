# Privatus-chat User Guide

A comprehensive guide to using Privatus-chat for secure and anonymous messaging.

## Table of Contents

1. [Getting Started](#getting-started)
2. [User Interface Overview](#user-interface-overview)
3. [Sending Messages](#sending-messages)
4. [Managing Contacts](#managing-contacts)
5. [Privacy Features](#privacy-features)
6. [Group Chats](#group-chats)
7. [File Sharing](#file-sharing)
8. [Voice & Video Calls](#voice--video-calls)
9. [Security Settings](#security-settings)
10. [Advanced Features](#advanced-features)
11. [Tips & Best Practices](#tips--best-practices)

## Getting Started

### First Launch

When you first launch Privatus-chat after installation:

1. **Identity Setup**: The application will generate your cryptographic keys
2. **Display Name**: Choose a name (can be anonymous)
3. **Privacy Level**: Select your desired privacy level
4. **Network Connection**: Wait for the application to connect to the network

### Understanding the Status Bar

The status bar at the bottom shows:
- 🌐 **Network Status**: Connected/Disconnected
- 🔒 **Encryption Status**: Active/Inactive
- 🎭 **Privacy Level**: Minimal/Standard/High/Maximum
- 👥 **Peer Count**: Number of connected peers

## User Interface Overview

### Main Window Components

```
┌─────────────────────────────────────────────┐
│  File  Settings  Help                       │ Menu Bar
├─────────────────────────────────────────────┤
│ ┌─────────┬─────────────────────────────┐   │
│ │Contacts │    Chat Area                │   │
│ │         │                             │   │
│ │ Alice ✅ │  [Messages appear here]    │   │
│ │ Bob   ⚠️ │                             │   │
│ │ Carol 🟢│                             │   │
│ │         │                             │   │
│ └─────────┴─────────────────────────────┘   │
│ [Type a message...            ] [Send 🔒]    │ Message Input
├─────────────────────────────────────────────┤
│ 🌐 Connected | 🔒 E2EE | 🎭 High | 👥 12    │ Status Bar
└─────────────────────────────────────────────┘
```

### Contact List Icons

- 🟢 **Green Circle**: Contact is online
- ⚫ **Black Circle**: Contact is offline
- ✅ **Check Mark**: Verified contact
- ⚠️ **Warning**: Unverified contact
- 🔒 **Lock**: End-to-end encryption active
- 🎭 **Mask**: Anonymous mode enabled

## Sending Messages

### Basic Messaging

1. **Select a Contact**: Click on a contact in the left panel
2. **Type Your Message**: Use the input field at the bottom
3. **Send**: Press Enter or click the Send button
4. **Encryption**: Messages are automatically encrypted (🔒 icon shows status)

### Message Features

- **Timestamps**: Each message shows when it was sent
- **Delivery Status**: 
  - ➡️ Sent
  - ✓ Delivered
  - ✓✓ Read
- **Encryption Indicator**: 🔒 for encrypted, 🔓 for unencrypted

### Special Message Types

**Formatted Text** (Markdown supported):
- **Bold**: `**text**` → **text**
- *Italic*: `*text*` → *text*
- `Code`: `` `code` `` → `code`
- Links: `[text](url)` → [text](url)

**Emojis**: Type `:` to open emoji picker

**Reactions**: Right-click a message to add reactions

## Managing Contacts

### Adding Contacts

1. **Click File → Add Contact** or press `Ctrl+N`
2. **Enter Contact Information**:
   - Display Name (required)
   - Public Key or Identity Code
   - Optional: Notes
3. **Verify Identity** (recommended):
   - Compare key fingerprints via secure channel
   - Mark as verified once confirmed

### Contact Verification

**Why Verify?**
- Ensures you're talking to the right person
- Prevents man-in-the-middle attacks
- Shows ✅ icon when verified

**How to Verify:**
1. Right-click contact → View Security Info
2. Compare the fingerprint with your contact
3. Use secure channel (in-person, phone call)
4. Click "Mark as Verified" once confirmed

### Organizing Contacts

- **Groups**: Create contact groups for organization
- **Favorites**: Star important contacts
- **Block**: Right-click → Block Contact
- **Search**: Use the search bar to find contacts

## Privacy Features

### Privacy Levels

**Minimal Privacy** 🟢
- Basic encryption
- Direct connections
- Faster performance
- Suitable for casual use

**Standard Privacy** 🟡
- Enhanced encryption
- Some traffic obfuscation
- Balanced performance
- Recommended for most users

**High Privacy** 🟠
- Onion routing enabled
- Traffic analysis resistance
- Anonymous identities available
- For sensitive communications

**Maximum Privacy** 🔴
- Full anonymity features
- Maximum security measures
- Performance trade-offs
- For highest threat models

### Anonymous Mode

Enable anonymous mode for specific conversations:

1. Click the 🎭 icon in chat window
2. Choose anonymity options:
   - **Ephemeral Identity**: Temporary identity for this chat
   - **Persistent Pseudonym**: Reusable anonymous identity
   - **Disposable**: One-time use identity

### Traffic Obfuscation

When enabled, Privatus-chat will:
- Pad messages to standard sizes
- Add random delays to messages
- Generate cover traffic
- Resist traffic analysis

## Group Chats

### Creating a Group

1. **File → New Group** or `Ctrl+G`
2. **Configure Group**:
   - Group Name
   - Privacy Settings
   - Member Permissions
3. **Add Members**: Select from your contacts
4. **Create**: Click Create Group

### Group Features

**Admin Controls**:
- Add/remove members
- Change group settings
- Moderate messages
- Assign roles

**Member Features**:
- Send messages
- Share files
- Voice/video calls
- View member list

### Group Privacy

- **Private Groups**: Invitation only, encrypted
- **Secret Groups**: Hidden from non-members
- **Anonymous Groups**: Members can use pseudonyms

## File Sharing

### Sending Files

1. **Drag & Drop**: Drag files into chat window
2. **File Menu**: Click attachment icon 📎
3. **Paste**: Ctrl+V to paste files/images

### File Types

**Supported**:
- Documents (PDF, DOC, TXT)
- Images (JPG, PNG, GIF)
- Videos (MP4, AVI, MOV)
- Audio (MP3, WAV, OGG)
- Archives (ZIP, RAR, 7Z)

**Size Limits**:
- Standard: 100MB per file
- Large files: Automatically chunked
- No limit with patience!

### File Security

- All files encrypted end-to-end
- Integrity verification
- Secure deletion after transfer
- Optional expiration dates

## Voice & Video Calls

### Making Calls

**Voice Call**:
1. Select contact
2. Click phone icon 📞
3. Wait for answer

**Video Call**:
1. Select contact
2. Click video icon 📹
3. Allow camera access

### Call Features

- **End-to-end encrypted**
- **Noise cancellation**
- **Echo reduction**
- **Quality adaptation**
- **Screen sharing**

### Call Privacy

- Voice anonymization available
- No IP address leakage
- Encrypted signaling
- Optional voice masking

## Security Settings

### Access Security Settings

**Settings → Security** or `Ctrl+Alt+S`

### Key Security Options

**Encryption**:
- Algorithm selection
- Key size preferences
- Perfect forward secrecy

**Authentication**:
- Two-factor authentication
- Biometric unlock
- Session management

**Privacy**:
- Message retention
- Metadata protection
- Screenshot blocking

**Network**:
- Proxy configuration
- Bridge relay usage
- Port settings

### Security Self-Test

Run periodic security checks:
1. Settings → Security → Run Self-Test
2. Review results
3. Fix any issues found

## Advanced Features

### Command Line Interface

Access CLI mode for power users:
```bash
privatus-chat --cli
```

Common commands:
- `/help` - Show commands
- `/status` - Connection status
- `/privacy <level>` - Change privacy
- `/verify <contact>` - Verify contact

### Automation & Scripting

**Webhooks**: Settings → Developer → Webhooks
- Message received
- Contact online
- File received

**API Access**: Enable in developer settings
- REST API for external apps
- WebSocket for real-time

### Backup & Sync

**Backup Your Data**:
1. Settings → Backup
2. Choose backup location
3. Set encryption password
4. Create backup

**Sync Across Devices**:
- Enable sync in settings
- Scan QR code on new device
- Automatic encrypted sync

## Tips & Best Practices

### Security Tips

1. **Always verify contacts** before sensitive conversations
2. **Use high privacy mode** for sensitive topics
3. **Regular security self-tests**
4. **Keep software updated**
5. **Use strong passwords**

### Privacy Tips

1. **Rotate identities** periodically
2. **Enable traffic obfuscation** in high-risk situations
3. **Use anonymous mode** when needed
4. **Clear message history** regularly
5. **Review privacy settings** monthly

### Performance Tips

1. **Adjust privacy level** based on needs
2. **Close unused group chats**
3. **Clear cache periodically**
4. **Limit file sharing** on slow connections
5. **Use wired connection** when possible

### Troubleshooting

**Can't connect?**
- Check firewall settings
- Try different privacy level
- Use bridge relays

**Messages not sending?**
- Check network connection
- Verify contact is online
- Check encryption settings

**Poor call quality?**
- Lower video resolution
- Check bandwidth
- Close other apps

## Getting Help

- **In-app Help**: Help → Documentation
- **Community Forum**: https://privatus-chat.org/forum
- **Security Issues**: security@privatus-chat.org
- **Bug Reports**: https://github.com/privatus-chat/issues

---

*Remember: Your privacy is our priority. Stay safe, stay private.*

*Last updated: December 2024*
*Version: 1.0.0* 