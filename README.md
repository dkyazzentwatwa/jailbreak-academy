# AI Guardian - LLM Security Training Platform

![AI Guardian Screenshot](img/Screenshot%202025-09-01%20at%2010.29.47%20AM.png)

## 🛡️ Overview

AI Guardian is an interactive cybersecurity training platform that helps security professionals and AI developers understand and defend against prompt injection attacks and jailbreaking techniques. Through a gamified 20-level progression system, users learn to identify, analyze, and neutralize various security threats targeting Large Language Models (LLMs).

## ✨ Features

### 🎮 Dual Mode System
- **Security Mode**: Real-time threat detection and content sanitization
- **Training Mode**: Progressive jailbreak simulation with 20 challenging levels

### 🔍 Advanced Threat Detection
- **SQL Injection** detection and prevention
- **Cross-Site Scripting (XSS)** protection
- **Prompt Injection** identification
- **Command Injection** blocking
- **Social Engineering** pattern recognition
- **Content Obfuscation** analysis

### 📊 Security Features
- Real-time threat analysis with detailed reporting
- Severity-based threat classification (Critical, High, Moderate, Low)
- Pattern-based detection engine
- DOMPurify integration for HTML sanitization
- Comprehensive security metrics tracking

### 🎯 Training Features
- 20 progressively challenging levels
- Hint system for learning assistance
- Performance scoring with bonus points
- Progress tracking and achievements
- Interactive feedback system

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn package manager

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/llm-sanitizer-59.git
cd llm-sanitizer-59
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

4. Open your browser and navigate to:
```
http://localhost:5173
```

## 💻 Usage

### Security Mode
1. Toggle to **SECURITY** mode using the header switch
2. Paste potentially malicious content into the input field
3. Click **ANALYZE_THREATS** to scan for security issues
4. Review the sanitized output and threat analysis

### Training Mode
1. Toggle to **TRAINING** mode using the header switch
2. Read the level objective and hints
3. Craft your jailbreak attempt
4. Click **EXECUTE_JAILBREAK** to test your attempt
5. Progress through all 20 levels to complete the training

## 🏗️ Tech Stack

- **Frontend**: React 18 + TypeScript
- **Styling**: Tailwind CSS + shadcn/ui components
- **Build Tool**: Vite
- **Security**: DOMPurify for XSS protection
- **State Management**: React hooks + localStorage
- **Testing**: Vitest

## 📂 Project Structure

```
src/
├── components/       # React components
│   ├── ui/          # shadcn/ui components
│   └── ...          # Game and security components
├── lib/             # Core logic
│   ├── sanitization-engine.ts  # Threat detection engine
│   ├── game-engine.ts         # Game mechanics
│   ├── game-levels.ts         # Level definitions
│   └── ...
├── types/           # TypeScript type definitions
└── pages/           # Application pages
```

## 🔒 Security Patterns Detected

- SQL Injection attempts
- XSS vectors and script injections
- Prompt injection and jailbreak attempts
- Command injection patterns
- Social engineering tactics
- Obfuscated content

## 🎮 Game Levels

The training mode includes 20 levels covering:
1. Basic prompt manipulation
2. Context switching techniques
3. Role-playing attacks
4. System prompt override attempts
5. Advanced obfuscation methods
6. Multi-stage attack chains
7. And more...

## 📈 Features in Development

- [ ] Backend API for persistent leaderboards
- [ ] Multi-player challenges
- [ ] Custom level editor
- [ ] Advanced analytics dashboard
- [ ] Export security reports
- [ ] Integration with popular LLM APIs

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Contact

- Email: littlehakr@protonmail.com
- Instagram: [@little_hakr](https://www.instagram.com/little_hakr/)
- TikTok: [@littlehakr](https://www.tiktok.com/@littlehakr)
- LinkedIn: [David Kyazze Ntwatwa](https://www.linkedin.com/in/david-kyazze-ntwatwa)
- LinkTree: [littlehakr](https://linktr.ee/littlehakr)

## 🙏 Acknowledgments

- Built with React and TypeScript
- UI components from [shadcn/ui](https://ui.shadcn.com/)
- Security sanitization powered by [DOMPurify](https://github.com/cure53/DOMPurify)
- Terminal effects inspired by classic cyberpunk aesthetics

---

**⚠️ Disclaimer**: This tool is for educational and defensive security purposes only. Use responsibly and ethically.
