#!/bin/bash

# =======================
# Input dari Pengguna
# =======================
read -p "🔗 Masukkan URL Panel Pterodactyl (contoh: https://panel.example.com): " PANEL_URL
read -p "🆔 Masukkan ID Node yang ingin ditambahkan allocation: " NODE_ID
read -p "🌐 Masukkan IP yang ingin digunakan: " IP
read -p "🔢 Masukkan port (pisahkan dengan spasi, contoh: 25565 8080 3000): " -a PORTS

# =======================
# Masuk ke Direktori Panel
# =======================
cd /var/www/pterodactyl || { echo "❌ Direktori Pterodactyl tidak ditemukan!"; exit 1; }

# =======================
# Buat API Key Admin
# =======================
echo "🔑 Membuat API Key Admin..."
API_KEY=$(php artisan p:admin:generate-token --name "API_SCRIPT" | grep "Your API Key" | awk '{print $4}')

if [ -z "$API_KEY" ]; then
  echo "❌ Gagal membuat API Key!"
  exit 1
fi

echo "✅ API Key berhasil dibuat: $API_KEY"

# =======================
# Tambahkan IP Allocation & Port
# =======================
echo "🛠️ Menambahkan IP Allocation & Port ke Node ID $NODE_ID..."

for PORT in "${PORTS[@]}"; do
  RESPONSE=$(curl -s -X POST "$PANEL_URL/api/application/nodes/$NODE_ID/allocations" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "{
      \"ip\": \"$IP\",
      \"port\": $PORT
    }")

  if echo "$RESPONSE" | grep -q "attributes"; then
    echo "✅ Berhasil menambahkan allocation: $IP:$PORT"
  else
    echo "❌ Gagal menambahkan allocation untuk $IP:$PORT"
    echo "Response: $RESPONSE"
  fi
done

# =======================
# Generate Token Wings
# =======================
echo "🔄 Menghasilkan token Wings untuk Node ID $NODE_ID..."

RESPONSE=$(curl -s -X POST "$PANEL_URL/api/application/nodes/$NODE_ID/configuration" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json")

TOKEN=$(echo "$RESPONSE" | jq -r '.attributes.token' 2>/dev/null)

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
  echo "✅ Token Wings berhasil dibuat: $TOKEN"
else
  echo "❌ Gagal membuat token Wings!"
  echo "Response: $RESPONSE"
fi

echo "🎉 Selesai! Semua proses telah selesai."
