//inits
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv'; 
import { createClient } from '@supabase/supabase-js';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'views')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

//initialize supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseClient = createClient(supabaseUrl, supabaseKey);
const supabaseAdmin = supabaseServiceRoleKey
    ? createClient(supabaseUrl, supabaseServiceRoleKey, {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    })
    : null;

app.route('/').get((req, res) => {
    res.render('index');
});
app.route('/contact').get((req, res) => {
    res.render('contact');
});

//LOGIN
app.route('/login').get((req, res) => {
    /*  const session = req.cookies.session;
    if (session) {
        return res.redirect('/dashboard');
    }  */
    res.render('login');
})
app.post('/login', async (req, res) => { 
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).render('login', { error: 'Email and password are required' });
        }
        
        const { data, error } = await supabaseClient.auth.signInWithPassword({
            email: email,
            password: password
        });
        
        if (error) {
            console.error('Login error:', error.message);
            return res.status(401).render('login', { error: 'Invalid email or password' });
        }
        
        if (data.user && data.session) {
            //2 day session cookie cuz yes
            res.cookie('session', JSON.stringify(data.session), { 
                maxAge: 2 * 24 * 60 * 60 * 1000,
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production'
            });
            res.redirect('/dashboard');
        } else {
            return res.status(401).render('login', { error: 'Authentication failed' });
        }
    } catch (err) {
        console.error('Server error during login:', err);
        return res.status(500).render('login', { error: 'Server error occurred' });
    }
});
app.route('/logout').get((req, res) => {
    res.clearCookie('session');
    res.redirect('/login');
});



//DASHBOARD & RELATED
app.route('/dashboard').get(async (req, res) => {
    const session = req.cookies.session;
    if (!session) {
        return res.redirect('/login');
    }
    
    try {
        const sessionData = JSON.parse(session);
        const { data: { user }, error: userError } = await supabaseClient.auth.getUser(sessionData.access_token);
        
        if (userError || !user) {
            return res.redirect('/login');
        }
          
        const { data: userData, error: dbError } = await supabaseClient
            .from('users')
            .select('name, dept')
            .eq('id', user.id)
            .single();
            
        if (dbError) {
            console.error('Database error:', dbError);
            return res.sendStatus(500).send('Internal Server Error');
        }
        res.cookie('userInfo', JSON.stringify({ name: userData.name || user.email, dept: userData.dept || 'Unknown' }), { 
            maxAge: 2 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production'
        });
        res.render('dashboard', { name: userData.name || user.email, dept: userData.dept || 'Unknown' });
        
    } catch (err) {
        console.error('Dashboard error:', err);
        res.redirect('/login');
    }
});
//URL SHORTENER WITH GIISCLUBS INTEGRATION
app.route('/urlshortener').get(async (req, res) => {
    const userInfo = req.cookies.userInfo ? JSON.parse(req.cookies.userInfo) : { name: 'Guest', dept: 'Unknown' };
    const { data: shortenedUrls, error } = await supabaseClient.from('urls').select('*');
    if (error) {
        console.error('Error fetching shortened URLs:', error);
    }
    console.log(shortenedUrls);
    res.render('urlshort', { name: userInfo.name, dept: userInfo.dept, shortenedUrls: shortenedUrls || [] });
});
app.post('/urlshort', async (req, res) => {
    const { originalUrl , newurl } = req.body;
    if (!originalUrl) {
        return res.status(400).render('urlshort', { error: 'Please provide a URL to shorten.' });
    }
    try {
        const response = await fetch('https://giisclubs.org/idadd', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ link: originalUrl, customId: newurl || undefined })
        });
        const data = await response.json();
        if (response.ok) {
        
            const { error: insertError } = await supabaseClient.from('urls').insert([
                { shortid: newurl, url: originalUrl }
            ]);
            console.log('Insert Error:', insertError);
            
            if (insertError) {
                console.error('Error inserting URL into database:', insertError);
            }
            console.log('Inserted URL:', updatedData);
            res.redirect('/urlshortener');
        }
        else {
            res.status(400).redirect('/urlshortener', { error: data.error || 'Error creating short URL.' });
        }
    } catch (err) {
        console.error('URL Shortener error:', err);
        res.status(500).redirect('/urlshortener', { error: 'Server error occurred.' });
    }
});
function deriveKey(secret) {
  return crypto.createHash('sha256').update(secret).digest();
}
function encrypt(text, secret) {
  const key = deriveKey(secret);
  const iv = crypto.randomBytes(16); 
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}
function decrypt(encryptedData, secret) {
  try {
    console.log('Decrypting with secret length:', secret.length);
    console.log('Encrypted data format:', encryptedData.includes(':') ? 'Valid (has IV)' : 'Invalid (no IV separator)');
    
    const key = deriveKey(secret);
    const parts = encryptedData.split(':');
    
    if (parts.length !== 2) {
      throw new Error('Invalid encrypted data format. Expected format: IV:EncryptedData');
    }
    
    const [ivHex, encrypted] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    
    console.log('IV length:', iv.length, 'Key length:', key.length);
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decrypt function error:', error.message);
    throw error;
  }
}
function createHttpError(status, message) {
    const error = new Error(message);
    error.status = status;
    return error;
}
function verifyMasterKey(masterKey) {
    if (!masterKey) {
        throw createHttpError(400, 'Master key is required');
    }
    if (masterKey !== process.env.MASTER_KEY) {
        throw createHttpError(403, 'Invalid master key');
    }
}
function ensureAdminClient() {
    if (!supabaseAdmin) {
        throw createHttpError(500, 'Server authentication is not configured');
    }
    return supabaseAdmin;
}
function sanitize(value) {
    return typeof value === 'string' ? value.trim() : '';
}

async function handleRoute(res, handler) {
    try {
        const payload = await handler();
        res.json({ success: true, ...payload });
    } catch (err) {
        const status = err.status || 500;
        const message = err.message || 'Server error occurred';
        if (!err.status) {
            console.error(err);
        }
        res.status(status).json({ success: false, message });
    }
}
app.route('/qrgen').get(async (req, res) => {
    const userInfo = req.cookies.userInfo ? JSON.parse(req.cookies.userInfo) : { name: 'Guest', dept: 'Unknown' };
    res.render('qrgen', { name: userInfo.name, dept: userInfo.dept});
});
  

//PASSWORD MANAGER ROUTES
app.route('/socialsmanager').get(async (req, res) => {
    const userInfo = req.cookies.userInfo ? JSON.parse(req.cookies.userInfo) : { name: 'Guest', dept: 'Unknown' };
    res.render('socials', { name: userInfo.name, dept: userInfo.dept});
});
app.post('/master2pass', async (req, res) => {
    const { masterKey } = req.body;
    
    if (masterKey !== process.env.MASTER_KEY) {
        console.log('Invalid master key provided');
        return res.status(403).json({ success: false, message: 'Invalid master key' });
    }
    
    try {
        console.log('Fetching passwords from database...');
        const { data: passwords, error } = await supabaseClient
            .from('passwords')
            .select('name, url, password');
            
        if (error) {
            console.error('Error fetching passwords:', error);
            return res.status(500).json({ success: false, message: 'Error fetching passwords' });
        }
        
        console.log('Fetched passwords:', passwords?.length || 0);
        
        const decryptedPasswords = [];
        for (const pwd of passwords || []) {
            try {
                console.log('Decrypting password for:', pwd.name);
                const decryptedPassword = decrypt(pwd.password, process.env.MASTER_KEY);
                decryptedPasswords.push({
                    name: pwd.name,
                    url: pwd.url,
                    password: decryptedPassword
                });
                console.log('Successfully decrypted password for:', pwd.name);
            } catch (decryptError) {
                console.error('Error decrypting password for', pwd.name, ':', decryptError);
            }
        }
        
        console.log('Sending response with', decryptedPasswords.length, 'passwords');
        res.json({ 
            success: true, 
            passwords: decryptedPasswords,
            message: 'Passwords retrieved successfully'
        });
        
    } catch (err) {
        console.error('Password manager error:', err);
        res.status(500).json({ success: false, message: 'Server error occurred' });
    }
});
app.post('/addpassword', async (req, res) => {
    const { name, url, password, masterKey } = req.body;
    
    if (!name || !url || !password || !masterKey) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    if (masterKey !== process.env.MASTER_KEY) {
        return res.status(403).json({ success: false, message: 'Invalid master key' });
    }
    
    try {
        console.log('Encrypting password for:', name);
        const encryptedPassword = encrypt(password, masterKey);
        
        const { error: insertError } = await supabaseClient
            .from('passwords')
            .insert([
                { 
                    name: name, 
                    url: url, 
                    password: encryptedPassword 
                }
            ]);
            
        if (insertError) {
            console.error('Error inserting password:', insertError);
            return res.status(500).json({ success: false, message: 'Error saving password' });
        }
        
        res.json({ 
            success: true, 
            message: 'Password saved successfully'
        });
        
    } catch (err) {
        console.error('Add password error:', err);
        res.status(500).json({ success: false, message: 'Server error occurred' });
    }
});
app.post('/master2users', (req, res) => handleRoute(res, async () => {
    const { masterKey } = req.body;
    verifyMasterKey(masterKey);

    const { data: users, error } = await supabaseClient
        .from('users')
        .select('id, email, name, dept')
        .order('name', { ascending: true });

    if (error) {
        console.error('Error fetching users:', error);
        throw createHttpError(500, 'Error fetching users');
    }

    return {
        users: users || [],
        message: 'Users retrieved successfully'
    };
}));

app.post('/users/create', (req, res) => handleRoute(res, async () => {
    const { masterKey, email, password, name, dept } = req.body;
    verifyMasterKey(masterKey);

    const trimmedEmail = sanitize(email).toLowerCase();
    const trimmedName = sanitize(name);
    const trimmedDept = sanitize(dept);
    const cleanPassword = typeof password === 'string' ? password : '';

    if (!trimmedEmail || !cleanPassword || !trimmedName || !trimmedDept) {
        throw createHttpError(400, 'All fields are required');
    }

    if (cleanPassword.length < 6) {
        throw createHttpError(400, 'Password must be at least 6 characters long');
    }

    const adminClient = ensureAdminClient();
    const { data: authData, error: authError } = await adminClient.auth.admin.createUser({
        email: trimmedEmail,
        password: cleanPassword,
        email_confirm: true
    });

    if (authError) {
        console.error('Supabase auth create user error:', authError);
        const status = authError.status || 500;
        throw createHttpError(status, authError.message || 'Error creating auth user');
    }
    
    const userId = authData.user?.id;

    const { error: insertError } = await supabaseClient
        .from('users')
        .insert([
            { id: userId, email: trimmedEmail, name: trimmedName, dept: trimmedDept }
        ]);
    if (insertError) {
        console.error('Error inserting user profile:', insertError);
        throw createHttpError(500, 'Error saving user profile');
    }
    return { message: 'User account created successfully' };
}));

app.post('/users/delete', (req, res) => handleRoute(res, async () => {
    const { masterKey, id } = req.body;
    verifyMasterKey(masterKey);

    const trimmedId = sanitize(id);

    if (!trimmedId) {
        throw createHttpError(400, 'User ID is required');
    }

    const adminClient = ensureAdminClient();

    const { error: authError } = await adminClient.auth.admin.deleteUser(trimmedId);

    if (authError) {
        console.error('Supabase auth delete error:', authError);
        const status = authError.status || 500;
        throw createHttpError(status, authError.message || 'Error removing auth user');
    }

    const { error: deleteError } = await supabaseClient
        .from('users')
        .delete()
        .eq('id', trimmedId);

    if (deleteError) {
        console.error('Error deleting user profile:', deleteError);
        throw createHttpError(500, 'Error deleting user profile');
    }

    return { message: 'User deleted successfully' };
}));
app.post('/editpassword', async (req, res) => {
    const { masterKey, originalName, name, url, password } = req.body;
    
    if (!masterKey || !originalName || !name || !url || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    if (masterKey !== process.env.MASTER_KEY) {
        return res.status(403).json({ success: false, message: 'Invalid master key' });
    }
    
    try {
        console.log('Editing password for:', originalName, '-> New name:', name);
        const encryptedPassword = encrypt(password, masterKey);
        
        if (originalName !== name) {
            const { error: deleteError } = await supabaseClient
                .from('passwords')
                .delete()
                .eq('name', originalName);
                
            if (deleteError) {
                console.error('Error deleting old password:', deleteError);
                return res.status(500).json({ success: false, message: 'Error updating password' });
            }
            
            const { error: insertError } = await supabaseClient
                .from('passwords')
                .insert([
                    { 
                        name: name, 
                        url: url, 
                        password: encryptedPassword 
                    }
                ]);
                
            if (insertError) {
                console.error('Error inserting updated password:', insertError);
                return res.status(500).json({ success: false, message: 'Error updating password' });
            }
        } else {
            const { error: updateError } = await supabaseClient
                .from('passwords')
                .update({ 
                    url: url, 
                    password: encryptedPassword 
                })
                .eq('name', originalName);
                
            if (updateError) {
                console.error('Error updating password:', updateError);
                return res.status(500).json({ success: false, message: 'Error updating password' });
            }
        }
        
        res.json({ 
            success: true, 
            message: 'Password updated successfully'
        });
        
    } catch (err) {
        console.error('Edit password error:', err);
        res.status(500).json({ success: false, message: 'Server error occurred' });
    }
});
app.post('/deletepassword', async (req, res) => {
    const { masterKey, name } = req.body;
    
    if (!masterKey || !name) {
        return res.status(400).json({ success: false, message: 'Master key and name are required' });
    }
    
    if (masterKey !== process.env.MASTER_KEY) {
        return res.status(403).json({ success: false, message: 'Invalid master key' });
    }
    
    try {
        console.log('Deleting password for:', name);
        
        const { error: deleteError } = await supabaseClient
            .from('passwords')
            .delete()
            .eq('name', name);
            
        if (deleteError) {
            console.error('Error deleting password:', deleteError);
            return res.status(500).json({ success: false, message: 'Error deleting password' });
        }
        
        res.json({ 
            success: true, 
            message: 'Password deleted successfully'
        });
        
    } catch (err) {
        console.error('Delete password error:', err);
        res.status(500).json({ success: false, message: 'Server error occurred' });
    }
});
app.route('/usermgr').get(async (req, res) => {
    const userInfo = req.cookies.userInfo ? JSON.parse(req.cookies.userInfo) : { name: 'Guest', dept: 'Unknown' };
    const { data: users, error } = await supabaseClient.from('users').select('id, email, name, dept');  
    res.render('usrmgr', { name: userInfo.name, dept: userInfo.dept, users: users || []}); 
});


//MASTER PASSWORD RESET--- FINISH LAST 
app.route('/masterreset').get((req, res) => {
    res.render('masterreset');
});
app.post('/masterreset', async (req, res) => {
    if (req.body.masterkey !== process.env.MASTER_KEY) {
        return res.status(403).send('Invalid master key');
    }
    res.send('Master Reset POST request received');
});

//404 HANDLER
app.route('/:path' ).get((req, res) => {
    res.status(404).render('404', { error: '404 - Page Not Found', subtitle: 'The page you are looking for does not exist. :(' });
});


//JUST SERVER STUFF
app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});
