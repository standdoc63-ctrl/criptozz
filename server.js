const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'] }));

const DB_PATH = path.join(__dirname, 'puple.json');

// JSON faylı yoxdursa avtomatik yarat
if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [] }, null, 2));
}

const readDB = () => JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
const writeDB = (data) => fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');

const maskEmail = (e) => { const [u, d] = e.split('@'); return `${u[0]}***@${d[0]}***.com`; };
const maskPhone = (p) => p.length < 4 ? '****' : `${p.slice(0,3)}***${p.slice(-4)}`;

// 📝 REGISTER
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, phone, password } = req.body;
        if (!username || !email || !phone || !password) {
            return res.status(400).json({ message: 'Bütün sahələr doldurulmalıdır.' });
        }
        if (password.length < 6) return res.status(400).json({ message: 'Parol ən az 6 simvol olmalıdır.' });

        const db = readDB();
        const exists = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
        if (exists) return res.status(409).json({ message: 'Bu istifadəçi adı artıq mövcuddur.' });

        const hash = await bcrypt.hash(password, 12);
        db.users.push({
            id: Date.now(),
            username,
            email,
            email_masked: maskEmail(email),
            phone,
            phone_masked: maskPhone(phone),
            password_hash: hash,
            registered_at: new Date().toISOString()
        });
        writeDB(db);
        res.status(201).json({ success: true, message: 'Uğurla qeydiyyatdan keçdiniz.' });
    } catch (err) {
        console.error('Register Xətası:', err);
        res.status(500).json({ message: 'Server daxili xəta baş verdi.' });
    }
});

// 🔑 LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const db = readDB();
        const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
        if (!user) return res.status(401).json({ message: 'İstifadəçi tapılmadı.' });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ message: 'Parol yanlışdır.' });

        res.json({
            success: true,
            user: {
                username: user.username,
                email: user.email_masked,
                phone: user.phone_masked,
                registered_at: user.registered_at
            }
        });
    } catch (err) {
        console.error('Login Xətası:', err);
        res.status(500).json({ message: 'Server daxili xəta.' });
    }
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Server hazır: http://localhost:${PORT}`));
