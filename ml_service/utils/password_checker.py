# File: ml-service/utils/password_checker.py
import re
import math
import string


COMMON_PASSWORDS = {
    'password', 'password123', '123456', '12345678', 'qwerty', 'abc123',
    'letmein', 'monkey', 'master', 'dragon', '111111', 'baseball',
    'iloveyou', 'trustno1', 'sunshine', 'princess', 'welcome',
    'shadow', 'superman', 'michael', 'football', 'pass', 'pass123',
    'admin', 'admin123', 'root', 'toor', 'test', 'guest', 'login',
    '1234', '12345', '123456789', '1234567890', 'qwerty123', 'password1',
}

KEYBOARD_PATTERNS = [
    'qwerty', 'asdf', 'zxcv', 'qazwsx', '1234', 'abcd', 'password',
    '!@#$', '!@#$%', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
]


def calculate_entropy(password):
    """Shannon entropy of the password."""
    if not password:
        return 0
    freq = {}
    for c in password:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(password)) * math.log2(f/len(password)) for f in freq.values())


def get_charset_size(password):
    """Return size of character set used."""
    size = 0
    if any(c.islower() for c in password): size += 26
    if any(c.isupper() for c in password): size += 26
    if any(c.isdigit() for c in password): size += 10
    if any(c in string.punctuation for c in password): size += 32
    return max(size, 1)


def estimate_crack_time(password):
    """Estimate crack time at 10 billion guesses/second (GPU cluster)."""
    charset = get_charset_size(password)
    combinations = charset ** len(password)
    guesses_per_second = 10_000_000_000  # 10 billion (GPU cluster)
    seconds = combinations / (2 * guesses_per_second)  # average case

    if seconds < 1:
        return 'Instantly'
    elif seconds < 60:
        return f'{int(seconds)} seconds'
    elif seconds < 3600:
        return f'{int(seconds/60)} minutes'
    elif seconds < 86400:
        return f'{int(seconds/3600)} hours'
    elif seconds < 2592000:
        return f'{int(seconds/86400)} days'
    elif seconds < 31536000:
        return f'{int(seconds/2592000)} months'
    elif seconds < 3153600000:
        return f'{int(seconds/31536000)} years'
    elif seconds < 315360000000:
        return f'{int(seconds/3153600000)} centuries'
    else:
        return 'Practically impossible'


def detect_patterns(password):
    """Detect common weak patterns."""
    issues = []
    lower = password.lower()

    if lower in COMMON_PASSWORDS:
        issues.append('This is one of the most commonly used passwords')

    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            issues.append(f'Contains keyboard pattern: {pattern}')

    if re.search(r'(.)\1{2,}', password):
        issues.append('Contains repeated characters (e.g. aaa, 111)')

    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', lower):
        issues.append('Contains sequential characters')

    if re.match(r'^\d+$', password):
        issues.append('Password is all numbers — add letters and symbols')

    if re.match(r'^[a-zA-Z]+$', password):
        issues.append('Password is all letters — add numbers and symbols')

    # Date patterns
    if re.search(r'(19|20)\d{2}', password):
        issues.append('Contains a year — common and easy to guess')

    if re.search(r'\d{2}[/\-]\d{2}[/\-]\d{2,4}', password):
        issues.append('Contains a date — avoid personal dates')

    return issues


def calculate_score(password):
    """Calculate password strength score 0-100."""
    score = 0

    # Length (0-30 points)
    length = len(password)
    if length >= 20:
        score += 30
    elif length >= 16:
        score += 25
    elif length >= 12:
        score += 20
    elif length >= 10:
        score += 14
    elif length >= 8:
        score += 8
    else:
        score += 2

    # Character variety (0-40 points)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if has_lower: score += 8
    if has_upper: score += 10
    if has_digit: score += 10
    if has_special: score += 12

    # Entropy bonus (0-20 points)
    entropy = calculate_entropy(password)
    score += min(int(entropy * 4), 20)

    # Penalties
    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        score = min(score, 10)
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            score = max(0, score - 15)
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 10)

    return min(100, max(0, score))


def get_suggestions(password):
    """Generate actionable improvement suggestions."""
    suggestions = []
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if len(password) < 12:
        suggestions.append('Make it at least 12 characters (16+ is ideal)')
    if not has_upper:
        suggestions.append('Add uppercase letters (A-Z)')
    if not has_lower:
        suggestions.append('Add lowercase letters (a-z)')
    if not has_digit:
        suggestions.append('Add numbers (0-9)')
    if not has_special:
        suggestions.append('Add special characters (!@#$%^&*)')
    if password.lower() in COMMON_PASSWORDS:
        suggestions.append('This password is in breach databases — change it immediately')

    return suggestions


def generate_strong_alternative():
    """Generate a strong random password example."""
    import random
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + '!@#$%^&*'
    return ''.join(random.choices(chars, k=16))


def analyze_password(password):
    """Full password security analysis."""
    score = calculate_score(password)
    crack_time = estimate_crack_time(password)
    patterns = detect_patterns(password)
    suggestions = get_suggestions(password)

    if score >= 80:
        strength_label = 'Very Strong'
        color = 'green'
    elif score >= 60:
        strength_label = 'Strong'
        color = 'lime'
    elif score >= 40:
        strength_label = 'Moderate'
        color = 'yellow'
    elif score >= 20:
        strength_label = 'Weak'
        color = 'orange'
    else:
        strength_label = 'Very Weak'
        color = 'red'

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    return {
        'score': score,
        'strength': strength_label,
        'color': color,
        'length': len(password),
        'crack_time': crack_time,
        'entropy': round(calculate_entropy(password), 2),
        'charset_size': get_charset_size(password),
        'checks': {
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_numbers': has_digit,
            'has_special': has_special,
            'length_ok': len(password) >= 12,
            'not_common': password.lower() not in COMMON_PASSWORDS,
        },
        'patterns_found': patterns,
        'suggestions': suggestions,
        'strong_alternative': generate_strong_alternative() if score < 60 else None,
    }