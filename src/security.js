const crypto = require('node:crypto');
function safeEqual(a,b) { const x=Buffer.from(String(a||'')); const y=Buffer.from(String(b||'')); return x.length===y.length && crypto.timingSafeEqual(x,y); }
function requireAuth(req,res,next) { if (!req.session.user) return res.status(401).json({error:'Please sign in first.'}); next(); }
function requireRole(...roles) { return (req,res,next)=> { if (!req.session.user) return res.status(401).json({error:'Please sign in first.'}); if (!roles.includes(req.session.user.role)) return res.status(403).json({error:'Your account does not have permission for this action.'}); next(); }; }
function monthValid(s) { return /^\d{4}-(0[1-9]|1[0-2])$/.test(String(s||'')); }
module.exports={safeEqual,requireAuth,requireRole,monthValid};
