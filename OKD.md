
# Instalacja klastra OKD/OpenShift
## Wstęp
Do nauki OpenShifta potrzebowałem jakiejś instacji deweloperskiej "do psucia". Głowne założenia - wsyztko musi być na maszynach wirtualnych, do uruchomienia na VirtualBoksie lub VMWare Workstation. Klaster ma składać się z 3 wezłów typu Control Plane (w dalszej części będę je nazywał master), które też obsługuja ruch aplikacyjny - czyli nie ma osobnych Compute Node. Takie rozwiązanie będzie odzwierciedlało klaster OpenShifta, na którym pracuję w firmie, ale ten mogę łatwiej psuć. Poza klasterem bedzie postawiona 1 dodatkowa maszyna - okd-bastion. Poza typowymi dla bastiona funkcjami (dostęp do klastra przez oc/kubectl) będzie też routerem, firewallem, serwerem DHCP, DNS, HTTP (potrzebne tylko na etapie instalacji w celu dostarczenia plików konfiguracyjnych instalatora), HAProxy oraz NFS dla storage'u klastra - w skrócie maszyną do wszystkiego poza OKD. 
Jeszcze tak na szybko - co to jest OKD? OKD to "The Community Distribution of Kubernetes that powersRed Hat OpenShift" - czyli w zasadzie darmowa wersja OpenShifta, która ma kilka ograniczeń, ale w wiekszości są to braki oficjalnych i certyfikowanych operatorów, dostarczanych w ramach OpenShifta. Co ciekawe - dotarły do mnie słuchy o przynajmniej jednej firmie, która migruje się lub luż się przemigrowała z OpenShifta na OKD w swoich środowiskach produkcyjnych.
## Postawienie maszyn wirtualnych
Będę uzywał VMWare Workstation, ale da się to wszystko zrobić np. na VirtualBoksie. Zaczynamy od wykreowania sieci - uruchamiam Virtual Network Editor i dodaję nową sieć (VMnet10) typu Host-only, IP podsieci 192.168.64.0, maska 255.255.255.0. Ważne - wyłączam DHCP dla tej sieci (będziemy stawiać własne DHCP). DHCP ze strony VMWare Workstation nie ma możliwości przypisania trwałych IP dla MAC Adresu.
Następnie tworzę 5 maszyn wirtualnych:
* okd-bastion
* okd-bootstrap
* okd-master01
* okd-master02
* okd-master03
Każda z nich ma 4 rdzenie, 8192 MiB RAM i 120GiB dysku. Ewentualnie, dla maszyny okd-bastion można dać więcej (a nawet sporo więcej) dysku, bo będzie potrzebny dla NFSa. Ja dodałem drugi dysk (500GiB) później.
Dla okd-bastion dodałem 2 interfejsy sieciowe - pierwszy jako bridged network, drugi jako host-only ze wskazaniem sieci na VMnet10.
Na maszynach bootrap i masterach należy podmontować iso Fedora CoreOS https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/38.20230430.3.1/x86_64/fedora-coreos-38.20230430.3.1-live.x86_64.iso - ja odpaliłem maszyny i wciśnąłem TAB na etapie boot loadera - aby system nie startował, ale maszyna aby była uruchomiona - bo potrzebuję pobrać ich MAC adresy, a te w VMWare są losowane po uruchomieniu.
## Maszyna okd-bastion
Teraz okd-bastion. Zainstalowałem na niej Oracle Linux 9.2, ale może być w zasadzie dowolny linux. Bez żadnych dziwactw, może poza tym, że dałem całość na 1 FS (czyli dysk podmontowany jako /, bez osobnych dla /home itp).
Po instalacji należy doinstalować kilka pakietów:
- epel-release 
- bind 
- bind-utils 
- haproxy 
- dhcp-server 
- httpd nfs-utils
- git

Dodatkowo warto zainstalować jq
```
wget -O jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64  
chmod +x jq  
sudo mv jq /usr/local/bin/  
jq --version
```
### Konfiguracja firewalla
U mnie interfejs zewnętrzny bastiona to enp160, który ma adres IP nadawany dynamicznie przez mój router. Drugim interfejsem jest enp192, który ma podany adres statyczny 192.168.64.1.
```
nmcli c mod ens192 connection.zone internal
nmcli c mod ens160 connection.zone external
firewall-cmd --permanent --zone=external --add-masquerade
firewall-cmd --permanent --zone=internal --add-masquerade 
firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o enp160 -j MASQUERADE
firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i enp192 -o enp160 -j ACCEPT
firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i enp160 -o enp192 -m state --state RELATED,ESTABLISHED -j ACCEPT
firewall-cmd --permanent --zone=external --add-port=9000/tcp
firewall-cmd --permanent --zone=external --add-port=80/tcp
firewall-cmd --permanent --zone=external --add-port=443/tcp
firewall-cmd --permanent --zone=trusted --add-source=192.168.64.0/24
```
### Konfiguracja DHCP
/etc/dhcp/dhcpd.conf - tu trzeba wstawić własne MAC adresy dla bootstrapa i masterów.
```
authoritative;
ddns-update-style interim;
default-lease-time 14400;
max-lease-time 14400;

option routers                  192.168.64.1;
option broadcast-address        192.168.64.255;
option subnet-mask              255.255.255.0;
option domain-name-servers      192.168.64.1;
option domain-search            "okd.lab.local";
option domain-name-servers      192.168.64.1;
option domain-name              "okd.lab.local";

subnet 192.168.64.0 netmask 255.255.255.0 {
  interface ens192;
  pool {
    range 192.168.64.21 192.168.64.60;
    # Static entries
    host okd-bootstrap { hardware ethernet 00:0C:29:D5:20:56; fixed-address 192.168.64.200; option host-name "okd-bootstrap";}
    host master01 { hardware ethernet 00:0C:29:08:EB:27; fixed-address 192.168.64.201; option host-name "okd-master01";}
    host master02 { hardware ethernet 00:0C:29:C0:B8:B3; fixed-address 192.168.64.202; option host-name "okd-master02";}
    host master03 { hardware ethernet 00:0C:29:AA:CC:72; fixed-address 192.168.64.203; option host-name "okd-master03";}
    # this will not give out addresses to hosts not listed above
    # deny unknown-clients;
  }
}
```
### Konfiguracja DNSa (named)
/etc/named.conf
```
options {
        listen-on port 53 { any; };
#       listen-on-v6 port 53 { ::1; };
        directory       "/var/named";
        dump-file       "/var/named/data/cache_dump.db";
        statistics-file "/var/named/data/named_stats.txt";
        memstatistics-file "/var/named/data/named_mem_stats.txt";
        recursing-file  "/var/named/data/named.recursing";
        secroots-file   "/var/named/data/named.secroots";
        allow-query     { any; };

        /*
         - If you are building an AUTHORITATIVE DNS server, do NOT enable recursion.
         - If you are building a RECURSIVE (caching) DNS server, you need to enable
           recursion.
         - If your recursive DNS server has a public IP address, you MUST enable access
           control to limit queries to your legitimate users. Failing to do so will
           cause your server to become part of large scale DNS amplification
           attacks. Implementing BCP38 within your network would greatly
           reduce such attack surface
        */
        recursion yes;
        forwarders {
                8.8.8.8;
                8.8.4.4;
        };

        //dnssec-enable yes;
        //dnssec-validation yes;

        /* Path to ISC DLV key */
        bindkeys-file "/etc/named.root.key";

        managed-keys-directory "/var/named/dynamic";

        pid-file "/run/named/named.pid";
        session-keyfile "/run/named/session.key";
};

logging {
        channel default_debug {
                file "data/named.run";
                severity dynamic;
        };
};

zone "." IN {
        type hint;
        file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
include "/etc/named/named.conf.local";
```
/etc/named/named.conf.local
```
zone "okd.lab.local" {
    type master;
    file "/etc/named/zones/db.okd.local"; # zone file path
};


zone "64.168.192.in-addr.arpa" {
    type master;
    file "/etc/named/zones/db.192.168.64";  # 192.168.64.0/24 subnet
};
```
/etc/named/zones/db.okd.local
```
$TTL    604800
@       IN      SOA     okd-bastion.okd.lab.local. admin.okd.lab.local. (
                  2     ; Serial
             604800     ; Refresh
              86400     ; Retry
            2419200     ; Expire
             604800     ; Negative Cache TTL
)

; name servers - NS records
    IN      NS      okd-bastion

; name servers - A records
okd-bastion.okd.lab.local.          IN      A       192.168.64.1

; OpenShift Container Platform Cluster - A records
okd-bootstrap.okd.lab.local.        IN      A      192.168.64.200
okd-master01.okd.lab.local.         IN      A      192.168.64.201
okd-master02.okd.lab.local.         IN      A      192.168.64.202
okd-master03.okd.lab.local.         IN      A      192.168.64.203

; OpenShift internal cluster IPs - A records
api.okd.lab.local.    IN    A    192.168.64.1
api-int.okd.lab.local.    IN    A    192.168.64.1
*.apps.okd.lab.local.    IN    A    192.168.64.1
etcd-0.okd.lab.local.    IN    A     192.168.64.201
etcd-1.okd.lab.local.    IN    A     192.168.64.202
etcd-2.okd.lab.local.    IN    A    192.168.64.203
console-openshift-console.apps.okd.lab.local.     IN     A     192.168.64.1
oauth-openshift.apps.okd.lab.local.     IN     A     192.168.64.1

; OpenShift internal cluster IPs - SRV records
_etcd-server-ssl._tcp.okd.lab.local.    86400     IN    SRV     0    10    2380    etcd-0.lab
_etcd-server-ssl._tcp.okd.lab.local.    86400     IN    SRV     0    10    2380    etcd-1.lab
_etcd-server-ssl._tcp.okd.lab.local.    86400     IN    SRV     0    10    2380    etcd-2.lab
```

/etc/named/zones/db.192.168.64
```
$TTL    604800
@       IN      SOA     okd-bastion.okd.lab.local. admin.okd.lab.local. (
                  7     ; Serial
             604800     ; Refresh
              86400     ; Retry
            2419200     ; Expire
             604800     ; Negative Cache TTL
)

; name servers - NS records
       IN    NS     okd-bastion.okd.lab.local.

; name servers - PTR records
1      IN    PTR    okd-services.okd.lab.local.

; OpenShift Container Platform Cluster - PTR records
200    IN    PTR    okd-bootstrap.okd.lab.local.
201    IN    PTR    okd-master01.okd.lab.local.
202    IN    PTR    okd-master02.okd.lab.local.
203    IN    PTR    okd-master03.okd.lab.local.
1      IN    PTR    api.okd.lab.local.
1      IN    PTR    api-int.okd.lab.local.
```
### Konfiguracja haproxy
 /etc/haproxy/haproxy.cfg
```
# Global settings
#---------------------------------------------------------------------
global
    maxconn     20000
    log         /dev/log local0 info
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    user        haproxy
    group       haproxy
    daemon

    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          300s
    timeout server          300s
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 20000

listen stats
    bind :9000
    mode http
    stats enable
    stats uri /
    stats refresh 15s
    monitor-uri /healthz



frontend okd_api_fe_6443
    bind :6443
    default_backend okd_api_be_6443
    mode tcp
    option tcplog

backend okd_api_be_6443
    balance source
    mode tcp
    server      okd-bootstrap 192.168.64.200:6443 check
    server      okd-master01 192.168.64.201:6443 check
    server      okd-master02 192.168.64.202:6443 check
    server      okd-master03 192.168.64.203:6443 check

frontend okd_machine_config_server_fe_22623
    bind :22623
    default_backend okd_machine_config_server_be_22623
    mode tcp
    option tcplog

backend okd_machine_config_server_be_22623
    balance source
    mode tcp
    server      okd-bootstrap 192.168.64.200:22623 check
    server      okd-master01 192.168.64.201:22623 check
    server      okd-master02 192.168.64.202:22623 check
    server      okd-master03 192.168.64.203:22623 check

frontend okd_http_ingress_traffic_fe_80
    bind :80
    default_backend okd_http_ingress_traffic_be_80
    mode tcp
    option tcplog

backend okd_http_ingress_traffic_be_80
    balance source
    mode tcp
    server      okd-bootstrap 192.168.64.200:80 check
    server      okd-master01 192.168.64.201:80 check
    server      okd-master02 192.168.64.202:80 check
    server      okd-master03 192.168.64.203:80 check

frontend okd_https_ingress_traffic_fe_443
    bind *:443
    default_backend okd_https_ingress_traffic_be_443
    mode tcp
    option tcplog

backend okd_https_ingress_traffic_be_443
    balance source
    mode tcp
    server      okd-bootstrap 192.168.64.200:443 check
    server      okd-master01 192.168.64.201:443 check
    server      okd-master02 192.168.64.202:443 check
    server      okd-master03 192.168.64.203:443 check
```
### Konfiguracja Apache HTTPD
Tu akurat najprościej - wszystko co trzeba zmienić to port serwera HTTP (bo 80 będzie zajęta przez haproxy)
```
sudo sed -i 's/Listen 80/Listen 8080/' /etc/httpd/conf/httpd.conf
```
### Konfiguracja NFSa
```
sudo systemctl enable nfs-server rpcbind
sudo systemctl start nfs-server rpcbind
sudo mkdir -p /var/nfs
sudo chmod -R 777 /var/nfs
sudo chown -R nobody:nobody /var/nfs
echo '/var/nfs 192.168.64.0/24(rw,sync,no_root_squash,no_all_squash,no_wdelay)' | sudo tee /etc/exports
```
## Rozpoczęcie instalacji OKD
Sama instalacja OKD składa się z 2 części. 
Pierwszą jest przygotowanie plików instalacyjnych. Te pliki będą zawierały całą startową konfigurację klastra (którą pozostawiam domyślną) i wskazanie kluczy SSH do załadowania na maszynach oraz pull secretów do pobrania obrazów z registry redhatowych. Z tych plików następnie są generowane pliki ignition, które zawierają instrukcje dla instalatora Fedora CoreOS, który robi całą resztę. 
W drugim etapie nejpierw odpalamy instalację CoreOSa na maszynie okd-bootstrap, gdzie zostaje postawiony minimalistyczny klaster, do którego następnie zostają dopięte węzły master. W momencie, gdy klaster na nodach master będzie juz w stanie sam działać to bootstrap się złozy i nie będzie więcej potrzebny - można go wyłączyć i usunąć. Z tego powodu nawet przy instalacjach typu baremetal maszyna bootstrap jest stawiana jako wirtualna - bo jest potrzebna tylko podczas instalacji.
### pull secret
Potrzebne będą nam pull secrety do pobrania obrazów z registry RedHata. Można to rozwiązać na przynajmniej 2 sposoby - użyć domyślnych lub założyć konto w RedHacie i pobrać stamtąd. 
Domyślne pull secret to
```
{
	“auths”:{
		“fake”:{“auth”: “bar”}
	}
}
```
Pozwalają one na instalację klastra, ale nie dają dostępu do wszystkich operatorów, dlatego warto pobrać sobie pull secrety ze strony RedHata. 
https://console.redhat.com/openshift/install/pull-secret 
```
{"auths":{
	"cloud.openshift.com":{"auth":"base64","email":"email@wp.pl"},
	"quay.io":{"auth":"BASE64","email":"email@wp.pl"},
	"registry.connect.redhat.com":{"auth":"BASE64","email":"email@wp.pl"},
	"registry.redhat.io":{"auth":"BASE64","email":"email@wp.pl"}
	}
}
```
### Klucze SSH
Tu sprawa jest dużo prostsza - czyli generujemy klucze SSH.
```
ssh-keygen
```
### Pobranie instalatora i klienta
Ze strony https://github.com/okd-project/okd/releases pobieramy pliki
- [openshift-client-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz](https://github.com/okd-project/okd/releases/download/4.12.0-0.okd-2023-04-16-041331/openshift-client-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz)
- [openshift-install-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz](https://github.com/okd-project/okd/releases/download/4.12.0-0.okd-2023-04-16-041331/openshift-install-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz)
```
wget https://github.com/okd-project/okd/releases/download/4.12.0-0.okd-2023-04-16-041331/openshift-client-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz
wget https://github.com/okd-project/okd/releases/download/4.12.0-0.okd-2023-04-16-041331/openshift-install-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz
tar -zxvf openshift-client-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz
tar -zxvf openshift-install-linux-4.12.0-0.okd-2023-04-16-041331.tar.gz
sudo mv kubectl oc openshift-install /usr/local/bin/  
oc version  
openshift-install version
```
### Przygotowanie instalacji
```
mkdir install_dir
```
Tworzę plik install_dir/install-config.yaml
```
apiVersion: v1
baseDomain: lab.local
metadata:
  name: okd

compute:
- hyperthreading: Enabled
  name: worker
  replicas: 0

controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: 3

networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14 
    hostPrefix: 23 
  networkType: OpenShiftSDN
  serviceNetwork: 
  - 172.30.0.0/16

platform:
  none: {}

fips: false

pullSecret: '{"auths":{"fake":{"auth": "bar"}}}' 
sshKey: 'ssh-ed25519 AAAA...'   
```
Ważne informacje - usrtawić domenę (baseDomain) i nazwę klastra (metadata.name) - razem wychodzi okd.lab.local czyli to, co jest skonfigurowane w DNSie.
Następnie należy usatwić klucz SSH i pull secret.
Jak plik będzie gotowy najlepiej go zbackupować - bo następne polecenie go usunie
```
cp ./install_dir/install-config.yaml ./install_dir/install-config.yaml.bak`
```
Teraz tworzymy manifesty
```
openshift-install create manifests --dir=install_dir/
```
Pozostaje nam utworzyć pliki ignition
```
openshift-install create ignition-configs --dir=install_dir/
```
### Hostowanie plików ignition
Teraz trzeba wystawić pliki na serwerze http
```
sudo mkdir /var/www/html/okd
sudo cp -R install_dir/* /var/www/html/okd/  
sudo chown -R apache: /var/www/html/  
sudo chmod -R 755 /var/www/html/
sudo setsebool -P httpd_read_user_content 1  
sudo systemctl enable httpd  
sudo systemctl start httpd
```
i można sprawdzić, czy wszystko bangla
```
curl localhost:8080/okd/metadata.json
```
### Pobranie obrazu Fedora CoreOS
Ze strony https://fedoraproject.org/coreos/download/?stream=stable należy pobrać 2 pliki: obraz raw Fedora CoreOS i plik sygnatury
```
wget https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/38.20230430.3.1/x86_64/fedora-coreos-38.20230430.3.1-metal.x86_64.raw.xz
wget https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/38.20230430.3.1/x86_64/fedora-coreos-38.20230430.3.1-metal.x86_64.raw.xz.sig
mv fedora-coreos-38.20230430.3.1-metal.x86_64.raw.xz fcos.raw.xz
mv fedora-coreos-38.20230430.3.1-metal.x86_64.raw.xz.sig fcos.raw.xz.sig
mv fcos.raw.* /var/www/html/okd
```
## Instalacja bootstrapa
Mamy odpaloną mszynę okd-bootstrap, ale zatrzymaną na bootloaderze. Trzeba tam dopisać parametry uruchomieniowe - wszystko w jednej linii, ja tu wstawiłem znaki nowej linii aby było łatwiej czytać. 
```
coreos.inst.install_dev=/dev/nvme0n1
coreos.inst.image_url=http://192.168.64.1:8080/okd/fcos.raw.xz 
coreos.inst.ignition_url=http://192.168.64.1:8080/okd/bootstrap.ign
```
## Instalacja masterów
Na masterach analogicznie - dopisujemy parametry uruchomieniowe. Jedyna różnica to uzycie pliku master.ign zamiast bootstrap.ign
```
coreos.inst.install_dev=/dev/nvme0n1
coreos.inst.image_url=http://192.168.64.1:8080/okd/fcos.raw.xz 
coreos.inst.ignition_url=http://192.168.64.1:8080/okd/master.ign
```
Teraz pozostaje czekać. Najłatwiej jest odpalić na bastionie 
```
openshift-install --dir=install_dir/ wait-for bootstrap-complete --log-level=info
```
W pewnym momencie pójdzie komunikat, że bootstrapowanie jest zakończone i można się pozbyć maszyny okd-bootstrap.
Klaster cały czas się stawia, do pobrania jest sporo obrazów. Postępy można obserwować narzędziem oc (openshiftowym kubectl)
```
export KUBECONFIG=~/install_dir/auth/kubeconfig
oc get nodes -o wide
oc get csr
```
Warto sprawdzić, czy wszystkie CSRy są zatwierdzone - jeżeli nie, to można je zatwierdzić ręcznie (u mnie nie było potrzeby)
```
oc get csr -ojson | jq -r '.items[] | select(.status == {} ) | .metadata.name' | xargs oc adm certificate approve
```
Gdy z polecenia 
```
oc get nodes
```
wszystkie nody będą jako Ready to znaczy, że CSRy są prawidłowo zatwierdzone. Teraz należy poczekać, aż zainstalują się wszystkie clusteroperatory
```
oc get clusteroperators
```
lub skrótowo
```
oc get co
```
U mnie to trwało długo, jakieś 2 godziny (mam wolne łącze). Warto też obserwować czy nie ma ErrImagePull, Crash czy innych błędów na podach przez
```
oc get pods -A
```
Takie pody usuwałem. 
Może jeszcze wystąpić problem z machine configiem. Gdy
```
oc get mcp
```
nie zmienia statusu długo warto sprawdzić co się dzieje. W tym celu zrobiłem
```
oc get mcp master -o yaml
```
i pojawiła się tam informacja
```
message: 'Node okd-master02 is reporting: "getting pending state from journal:
      invalid character ''U'' looking for beginning of value", Node okd-master03 is
      reporting: "getting pending state from journal: invalid character ''U'' looking
      for beginning of value"'
```
Jest to problem z journalem. W tym celu zalogowałem sie na podane nody
```
ssh core@okd-master02.okd.lab.local
sudo -i
```
```
[root@okd-master02 ~]# journalctl --verify
Journal file /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@0005fc3742709c54-6eca9ce9bfe3ba10.journal~ uses an unsupported feature, ignoring file.
Use SYSTEMD_LOG_LEVEL=debug journalctl --file=/var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@0005fc3742709c54-6eca9ce9bfe3ba10.journal~ to see the details.
PASS: /run/log/journal/b6e26c4db861474baaf198d6ef590c14/system.journal
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@9568609074994ae3930a1fa8619a9c92-0000000000000001-0005fc374221691a.journal
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/user-1000@ecb0a8ca75ee43acb8fb7aa5b5371224-000000000000847e-0005fc381cd80d81.journal
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@9568609074994ae3930a1fa8619a9c92-00000000000084bf-0005fc381d13973f.journal
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/user-1000@ecb0a8ca75ee43acb8fb7aa5b5371224-00000000000084c2-0005fc381d16f9f2.journal
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@9568609074994ae3930a1fa8619a9c92-000000000000ad1b-0005fc384862d10e.journal
390c80: Data object references invalid entry at 4e1da0
File corruption detected at /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system.journal:4e19d0 (of 8388608 bytes, 61%).
FAIL: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system.journal (Bad message)
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/user-1000@ecb0a8ca75ee43acb8fb7aa5b5371224-000000000000ad1e-0005fc384863d4c7.journal
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/user-1000.journal
```
Tu mamy informacje o problemach z journalami. Usunąłem wpisy z journali
```
[root@okd-master02 ~]# journalctl --vacuum-time=1m
Journal file /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@0005fc3742709c54-6eca9ce9bfe3ba10.journal~ uses an unsupported feature, ignoring file.
Use SYSTEMD_LOG_LEVEL=debug journalctl --file=/var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@0005fc3742709c54-6eca9ce9bfe3ba10.journal~ to see the details.
Vacuuming done, freed 0B of archived journals from /run/log/journal.
Vacuuming done, freed 0B of archived journals from /run/log/journal/b6e26c4db861474baaf198d6ef590c14.
Vacuuming done, freed 0B of archived journals from /var/log/journal.
Deleted archived journal /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@0005fc3742709c54-6eca9ce9bfe3ba10.journal~ (8.0M).
Deleted archived journal /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@9568609074994ae3930a1fa8619a9c92-0000000000000001-0005fc374221691a.journal (35.3M).
Deleted archived journal /var/log/journal/674cc4f6256143379fd7935e328f9d5a/user-1000@ecb0a8ca75ee43acb8fb7aa5b5371224-000000000000847e-0005fc381cd80d81.journal (3.5M).
Deleted archived journal /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@9568609074994ae3930a1fa8619a9c92-00000000000084bf-0005fc381d13973f.journal (12.1M).
Deleted archived journal /var/log/journal/674cc4f6256143379fd7935e328f9d5a/user-1000@ecb0a8ca75ee43acb8fb7aa5b5371224-00000000000084c2-0005fc381d16f9f2.journal (3.6M).
Deleted archived journal /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system@9568609074994ae3930a1fa8619a9c92-000000000000ad1b-0005fc384862d10e.journal (22.7M).
Deleted archived journal /var/log/journal/674cc4f6256143379fd7935e328f9d5a/user-1000@ecb0a8ca75ee43acb8fb7aa5b5371224-000000000000ad1e-0005fc384863d4c7.journal (3.7M).
Vacuuming done, freed 89.2M of archived journals from /var/log/journal/674cc4f6256143379fd7935e328f9d5a.
```
Ponowna weryfikacja przebiegła prawidłowo
```
[root@okd-master02 ~]# journalctl --verify
PASS: /run/log/journal/b6e26c4db861474baaf198d6ef590c14/system.journal
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/system.journal
PASS: /var/log/journal/674cc4f6256143379fd7935e328f9d5a/user-1000.journal
```
Teraz Machine config się zakończył prawidłowo.
Klaster działa. Można się zalogować do konsoli. Adres konsoli mozna odczytać przy uzyciu oc
```
oc whoami --show-console
```
W tym przypadku jest to https://console-openshift-console.apps.okd.lab.local
Aby suię zalogować nalezy podać uzytkownika kubeadmin i hasła z pliku install_dir/auth/kubeadmin-password
Teraz pozostaje utworzenie uzytkonika i skonfigurowanie storage'u.
## Utworzenie użytkowników
Czas utworzyć uzytkownika. Z kubeadmin nie należy bezpośrednio korzystać, warto potworzyć użytkowników imiennych. Najprostszym sposobem jest uzycie htpasswd. Najpierw wygenerujmy plik htpasswd
```
htpasswd -c -B -b users.htpasswd testuser testpassword
```
Następnie można załadować ten plik
```
oc create secret generic htpass-secret --from-file=htpasswd=users.htpasswd -n openshift-config
```
Aby z tego korzystać należy utworzyć htpasswd_provider. W tym celu należy tuworzyć plik htpasswd_provider.yaml
```
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - name: htpasswd_provider 
    mappingMethod: claim 
    type: HTPasswd
    htpasswd:
      fileData:
        name: htpass-secret 
```
i załadować go do klastra
```
oc apply -f htpasswd_provider.yaml
```
Teraz czas nadać uprawnienia. Pierwszemu uzytkownikowi warto nadać cluster-admin (czyli globalnego admina)
```
oc adm policy add-cluster-role-to-user cluster-admin testuser
```
Trzeba poczekać chwilę (u mnie ok. minuty) i po wejściu na konsolę zostaniemy przekirowani na ekran wybory providera tożsamości.
## Konfiguracja storage'u
Aby klaster był całkowicie funkcjonalny brakuje ostatniej rzeczy - podłączenia storage'u. Na okd-bastion mamy skonfigurowany zasób NFS /var/nfs udostępniony dla sieci 192.168.64.0/24. Aby z niego skorzystać możemy podejść na 2 sposoby. W wariancie prostszym można konfigurować Persistent Volume. Konfigurując PV wskazuje się adres IP serwera i ścieżkę do zasobu, np. tak:
```
apiVersion: v1
kind: PersistentVolume
metadata:
  name: nfs1-pv
spec:
  capacity:
    storage: 100Gi
  accessModes:
    - ReadWriteMany
  persistentVolumeReclaimPolicy: Retain
  nfs:
    path: /var/nfs/nfs1
    server: 192.168.64.1 
```
Zaletą jest to, że działa to bez żadnych dodatkowych operatorów, wadą - że musimy definiować takie woluminy samodzielnie. 
Jest drugie rozwiązanie - utworzenie Storage Class. Niestety, kubernetes (ani też OpenShift) nie ma wbudowanej storage classy do obsługi NFS. Jest jednak rozwiązanie w postaci zewnętrznego provisionera, co prawda niedostępnego przez OperatorHuba w OKD czy OpenShifcie.
Widziałem przynajmniej 2 takie rozwiązania, ja wybrałem # Kubernetes NFS Subdir External Provisioner (https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner). Na githubie jest ładna instrukcja, nawet zawierająca osobną część dla OpenShifta. W zasadzie całość to przepisanie fragmentu tej instrukcji, ale myślę, że warto to zawrzeć dla kompletności instrukcji.
Zaczynamy od sklonowania repozytorium:
```
git clone https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner.git
cd nfs-subdir-external-provisioner
```
Należy zacząć od utworzenia projektu/namespace'u dla provisionera, ja wybrałem "nfs-provisioner". Zatem najpierw tworzymy projekt:
```
oc new-project nfs-provisioner
```
Po utrozeniu projektu zostanie on automatycznie wybrany. Teraz jedziemy dokładnie według instrukcji:
```
NAMESPACE=`oc project -q`
sed -i'' "s/namespace:.*/namespace: $NAMESPACE/g" ./deploy/rbac.yaml ./deploy/deployment.yaml
oc create -f deploy/rbac.yaml
oc adm policy add-scc-to-user hostmount-anyuid system:serviceaccount:$NAMESPACE:nfs-client-provisioner
```
Następnie w pliku deplo/deployment.yaml należy ustawić adres do serwera NFS
```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nfs-client-provisioner
  labels:
    app: nfs-client-provisioner
  # replace with namespace where provisioner is deployed
  namespace: nfs-provisioner
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: nfs-client-provisioner
  template:
    metadata:
      labels:
        app: nfs-client-provisioner
    spec:
      serviceAccountName: nfs-client-provisioner
      containers:
        - name: nfs-client-provisioner
          image: registry.k8s.io/sig-storage/nfs-subdir-external-provisioner:v4.0.2
          volumeMounts:
            - name: nfs-client-root
              mountPath: /persistentvolumes
          env:
            - name: PROVISIONER_NAME
              value: k8s-sigs.io/nfs-subdir-external-provisioner
            - name: NFS_SERVER
              value: 192.168.64.1
            - name: NFS_PATH
              value: /var/nfs
      volumes:
        - name: nfs-client-root
          nfs:
            server: 192.168.64.1
            path: /var/nfs
```
Teraz należy załadować ten manifest
```
oc apply -f deploy/deployment.yaml
```
Mając gotowego provisionera mozna utworzyć strorageclass. Domyślna jest w pliku deploy/class.yaml. Ja zdecydowałem się jednak minimalnie ją zmienić - a mianowicie ustawić jako domyślą:
```
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
  name: nfs-client
parameters:
  onDelete: delete
  pathPattern: ${.PVC.namespace}/${.PVC.annotations.nfs.io/storage-path}
provisioner: k8s-sigs.io/nfs-subdir-external-provisioner
```
## Podsumowanie
To kończy proces instalacji i minimalnej konfiguracji klastra OKD. 
W przypadku "pełnego" OpenShifta (platnego) proces instalacji jest identyczny, różnice to pobranie właściwego instalatora (zamiast OKD z Githuba należy pobrać OpenShift od RedHata). Oczywiście, nic nmie stoi na przeszkodzie aby w swoim labie postawić taki klaster - istnieje wersja testowa na 60 dni. Całość do pobrania z https://console.redhat.com/openshift/downloads.
Na zakończenie chciałbym jeszcze wskazać 2 ciekawe źrodła - jest to instrukcja instalacji klastra w wersji 4.5 autorstwa Craiga Robinsona https://itnext.io/guide-installing-an-okd-4-5-cluster-508a2631cbee oraz pewnego rodzaju uzupełnienie w postaci zapisu streama z instalacji według tej instukcji  https://www.youtube.com/watch?v=qh1zYW7BLxE. Warto przejrzeć też inne wpisy na blogu Craiga - jest tam wiele instrukcji dotyczących instalacji OpenShifta na różne sposoby.
Przy tworzeniu tej istrukcji pomocny też był ocp4-helpernode https://github.com/redhat-cop/ocp4-helpernode - zautomatyzowany ansiblem sposób budowy bastiona. Właśnie z niego zaczerpnąłem pomysł postawienie własnego serwera DHCP a nie opieranie się na dodatkowej maszynie z postawionym pfsensem. Helpernode używa DHCP, jednak jest nastawiony na 
<!--stackedit_data:
eyJoaXN0b3J5IjpbNzMyNDIxNDI3LDc1MTUyOTM3OF19
-->