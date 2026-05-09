const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // Frontend-dən gələn sorğulara icazə

const DB = path.join(__dirname, 'puple.json');
const initDB = () => { if (!fs.existsSync(DB)) fs.writeFileSync(DB, JSON.stringify({ users: [] }, null, 2)); };
initDB();

// Maskalama funksiyaları
const maskEmail = (e) => { const [u, d] = e.split('@'); return `${u[0]}***@${d[0]}***.com`; };
const maskPhone = (p) => p.length < 4 ? '****' : p.slice(0, 3) + '***' + p.slice(-4);

// 📝 REGISTER
app.post('/api/register', async (req, res) => {
    const { username, email, phone, password } = req.body;
    if (!username || !email || !phone || !password) return res.status(400).json({ message: 'Bütün sahələr doldurulmalıdır.' });
    if (password.length < 6) return res.status(400).json({ message: 'Parol ən az 6 simvol olmalıdır.' });

    const db = JSON.parse(fs.readFileSync(DB));
    if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
        return res.status(409).json({ message: 'Bu istifadəçi adı artıq mövcuddur.' });

    const hash = await bcrypt.hash(password, 12);
    db.users.push({
        id: Date.now(),
        username,
        email: email,               // Doğrulama üçün saxlanılır
        email_masked: maskEmail(email), // JSON-da görünən versiya
        phone: phone,
        phone_masked: maskPhone(phone), // JSON-da görünən versiya
        password_hash: hash,        // Parol heç vaxt açıq saxlanmır
        registered_at: new Date().toISOString()
    });
    fs.writeFileSync(DB, JSON.stringify(db, null, 2));
    res.json({ success: true, message: 'Qeydiyyat tamamlandı.' });
});

// 🔑 LOGIN
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const db = JSON.parse(fs.readFileSync(DB));
    const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.status(401).json({ message: 'İstifadəçi tapılmadı.' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ message: 'Parol yanlışdır.' });

    // Frontend-ə yalnız maskalanmış məlumat göndərilir
    res.json({
        success: true,
        user: {
            username: user.username,
            email: user.email_masked,
            phone: user.phone_masked,
            registered_at: user.registered_at
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server işləyir: http://localhost:${PORT}`));
