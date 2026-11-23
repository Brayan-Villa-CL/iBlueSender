# NO NEED MACOS SERVER CONFIGURED

# iBlueSender
iMessage Proyect / Python Lang


# PREPARE

**Windows**

cd iBlueSender

python -m pip install requests pbkdf2 pycryptodome srp cryptography



**MacOS**

cd iBlueSender

python3 -m venv Blue

source Blue/bin/activate

python3 -m pip install requests pbkdf2 pycryptodome srp cryptography




# USAGE

**For register new identity**

python(3) login_im.py -e (AppleID) -p (Password)

- You can received 2FA for SMS  or trust Device
- 
- BAA Authentication is implemented
- 
- You can Relogin in same account



**After register identity**

Copy session cached in actual directory

cp tmp/session_cache.json ./


# SEND IMESSAGES

**python(3) iMessage.py --to destination@phoneEmail.com --message "Your message"


# RECEIVED IMESSAGES NOTIFICATION

**python(3) iMessage.py --listen
