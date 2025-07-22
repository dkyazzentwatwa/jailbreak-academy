
import { useEffect, useState } from 'react';

export const TerminalEffects = () => {
  const [matrixChars, setMatrixChars] = useState<Array<{
    id: number;
    char: string;
    left: number;
    duration: number;
    delay: number;
  }>>([]);

  useEffect(() => {
    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン'.split('');
    const newChars = Array.from({ length: 50 }, (_, i) => ({
      id: i,
      char: chars[Math.floor(Math.random() * chars.length)],
      left: Math.random() * 100,
      duration: 3 + Math.random() * 4,
      delay: Math.random() * 5,
    }));
    
    setMatrixChars(newChars);

    // Update characters periodically
    const interval = setInterval(() => {
      setMatrixChars(prev => prev.map(char => ({
        ...char,
        char: chars[Math.floor(Math.random() * chars.length)]
      })));
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <>
      {/* Scanning line */}
      <div className="scan-line" />
      
      {/* Matrix background */}
      <div className="matrix-bg">
        {matrixChars.map(({ id, char, left, duration, delay }) => (
          <div
            key={id}
            className="matrix-char"
            style={{
              left: `${left}%`,
              animationDuration: `${duration}s`,
              animationDelay: `${delay}s`,
            }}
          >
            {char}
          </div>
        ))}
      </div>
    </>
  );
};
