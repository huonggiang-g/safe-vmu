const API_BASE = "https://safe-vmu.onrender.com/api"; 

const savedToken = localStorage.getItem('safeToken');
const savedUser = localStorage.getItem('safeUser');
const savedRoles = localStorage.getItem('safeRoles');
const currentPath = window.location.pathname;

const isAuthPage = currentPath.includes('login.html') || currentPath.includes('register.html');

// Chặn người lạ chưa đăng nhập
if (!savedToken && !isAuthPage) {
    window.location.href = '/login.html';
}

// Đã đăng nhập thì không cho vào lại trang Đăng nhập
if (savedToken && isAuthPage) {
    window.location.href = '/index.html';
}

function doLogout() {
    localStorage.removeItem('safeToken');
    localStorage.removeItem('safeUser');
    localStorage.removeItem('safeRoles');
    window.location.href = '/login.html';
}

function getCurrentUser() { return savedUser ? JSON.parse(savedUser) : null; }
function getCurrentRoles() { return savedRoles ? JSON.parse(savedRoles) : null; }

function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + savedToken
    };
}