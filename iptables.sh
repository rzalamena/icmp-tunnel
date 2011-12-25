#!/bin/sh
ip6tables-save > backup.`date +%H_%M_%S`
ip6tables -F INPUT
ip6tables -F OUTPUT
ip6tables -F FORWARD
ip6tables -X ACEITA_ICMP
ip6tables -X REJEITA_TUDO

# mantem conexoes abertas rodando
ip6tables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT 
ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# aceita ICMP6
ip6tables -N ACEITA_ICMP
ip6tables -A OUTPUT -p ipv6-icmp -j ACEITA_ICMP
ip6tables -A INPUT -p ipv6-icmp -j ACEITA_ICMP
ip6tables -A FORWARD -p ipv6-icmp -j ACEITA_ICMP
ip6tables -A ACEITA_ICMP -j LOG --log-level info --log-prefix "ICMP"
ip6tables -A ACEITA_ICMP -j ACCEPT

# senao for ICMP6 rejeita
ip6tables -N REJEITA_TUDO
ip6tables -A OUTPUT -j REJEITA_TUDO
ip6tables -A INPUT -j REJEITA_TUDO
ip6tables -A FORWARD -j REJEITA_TUDO
ip6tables -A REJEITA_TUDO -j LOG --log-level info --log-prefix "QUALQUER_OUTRO"
ip6tables -A REJEITA_TUDO -j DROP
