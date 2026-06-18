mkdir -p /fs
mount -t ext4 device0 /fs

echo "Running setuid benchmark (busybox id loop)..."
time for i in $(seq 1 1000); do
  id > /dev/null
done
echo "Benchmark loop finished."
exit 0
