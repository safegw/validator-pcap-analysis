# validator-pcap-analysis

Use nice -n 19 if you're running it on the validator itself

```
# Screen 1
# Collect TPU stats
sudo tcpdump -i <your_nic> 'ip dst host <your_validator_ip> and udp dst port 8003' -w - \
  | zstdmt -o dump.pcap.zst

# Screen 2
# Analyze TPU stats
git clone https://github.com/Blockdaemon/validator-pcap-analysis --branch csv
cd validator-pcap-analysis
cargo build --release
zstdcat /data/dump.pcap.zst \
  | ./target/release/validator-pcap-analysis - \
  | mlr --csv uniq -g src_ip,signature -c \
        then stats1 -g src_ip -a sum,count,mean,median,max -f count \
        then sort -nr count_sum \
  > tpu_list.txt
  ```
  
  To pretty print do mlr --icsv --opprint cat < tpu_list.txt
  
  Thanks to Richard | Blockdaemon and CherryWorm from Solana Discord Community
