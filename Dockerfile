FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    wget gnupg2 \
    # Xvfb virtual framebuffer (required for uc + xvfb=True)
    xvfb \
    # Tkinter for PyAutoGUI / MouseInfo (used by solve_captcha)
    python3-tk python3-dev \
    # Chrome runtime dependencies
    fonts-liberation libasound2 libatk-bridge2.0-0 libatk1.0-0 \
    libcups2 libdbus-1-3 libdrm2 libgbm1 libgtk-3-0 libnspr4 \
    libnss3 libxcomposite1 libxdamage1 libxrandr2 xdg-utils \
    libx11-xcb1 libxss1 libxtst6 libpango-1.0-0 libcairo2 \
    && wget -q -O /tmp/chrome.key https://dl.google.com/linux/linux_signing_key.pub \
    && gpg --dearmor < /tmp/chrome.key > /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/* /tmp/chrome.key

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "get-creds-cdp.py"]