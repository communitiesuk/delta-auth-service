UPDATE user_audit
SET action = 'user_created_by_self_register'
WHERE action = 'self_register';

UPDATE user_audit
SET action = 'reset_password_email'
WHERE action = 'forgot_password_email';

UPDATE user_audit
SET action = 'user_created_by_sso'
WHERE action = 'sso_user_created';
