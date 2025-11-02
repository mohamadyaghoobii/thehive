# Troubleshooting

## Browser cannot reach port 80 from client
- Verify network ACLs / hypervisor port groups / cloud security groups.
- On server:
  ```bash
  ss -lntp | egrep ':80|:9000'
  sudo tcpdump -ni <iface> 'tcp port 80'
  ```

## Nginx shows 404 on `/index.html` but `/api/status` is OK
- Ensure TheHive serves UI (the SPA) on root and Nginx proxies to 127.0.0.1:9000:
  ```bash
  curl -i http://127.0.0.1:9000/index.html
  curl -i http://127.0.0.1:9000/api/status
  nginx -t && sudo systemctl reload nginx
  ```

## Elasticsearch fails to start
- Check logs and the required kernel tunable:
  ```bash
  journalctl -u elasticsearch -n 200 --no-pager
  sudo sysctl -w vm.max_map_count=262144
  curl -s http://127.0.0.1:9200 | jq .
  ```

## Cassandra not ready
- Wait a bit or check:
  ```bash
  journalctl -u cassandra -n 200 --no-pager
  ss -lnt | grep ':9042'
  cqlsh -e "DESCRIBE KEYSPACES"
  ```

## TheHive service exits with errors
- Show recent logs:
  ```bash
  journalctl -u thehive -n 200 --no-pager
  ```
- Validate config file:
  ```bash
  sudo -u thehive test -r /etc/thehive/application.conf && echo OK
  ```
