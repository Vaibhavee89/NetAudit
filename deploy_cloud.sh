#!/bin/bash
# NetAudit Cloud Deployment Script
# For Ubuntu/Debian servers

echo "🛡️  NetAudit Cloud Deployment Script"
echo "=================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install dependencies
echo "🔧 Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-venv nmap git nginx ufw

# Create application user
echo "👤 Creating application user..."
sudo useradd -m -s /bin/bash netaudit
sudo usermod -aG sudo netaudit

# Clone/setup application
echo "📁 Setting up application..."
sudo -u netaudit mkdir -p /home/netaudit/netaudit-app
cd /home/netaudit/netaudit-app

# Copy files (assuming they're in current directory)
sudo cp -r * /home/netaudit/netaudit-app/
sudo chown -R netaudit:netaudit /home/netaudit/netaudit-app/

# Create virtual environment
echo "🐍 Setting up Python environment..."
sudo -u netaudit python3 -m venv venv
sudo -u netaudit /home/netaudit/netaudit-app/venv/bin/pip install -r requirements_webapp.txt

# Create systemd service
echo "⚙️  Creating systemd service..."
sudo tee /etc/systemd/system/netaudit.service > /dev/null <<EOF
[Unit]
Description=NetAudit Web Application
After=network.target

[Service]
Type=simple
User=netaudit
WorkingDirectory=/home/netaudit/netaudit-app
Environment=PATH=/home/netaudit/netaudit-app/venv/bin
ExecStart=/home/netaudit/netaudit-app/venv/bin/python webapp.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure firewall
echo "🔥 Configuring firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow 5000
sudo ufw allow 80
sudo ufw allow 443

# Configure nginx (optional reverse proxy)
echo "🌐 Configuring nginx..."
sudo tee /etc/nginx/sites-available/netaudit > /dev/null <<EOF
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/netaudit /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx

# Start services
echo "🚀 Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable netaudit
sudo systemctl start netaudit
sudo systemctl enable nginx
sudo systemctl start nginx

# Display status
echo "✅ Deployment complete!"
echo ""
echo "📊 Service Status:"
sudo systemctl status netaudit --no-pager -l
echo ""
echo "🌐 Access your NetAudit application at:"
echo "   http://$(curl -s ifconfig.me)"
echo "   http://$(hostname -I | awk '{print $1}')"
echo ""
echo "📝 Useful commands:"
echo "   sudo systemctl status netaudit    # Check status"
echo "   sudo systemctl restart netaudit   # Restart service"
echo "   sudo journalctl -u netaudit -f    # View logs" 