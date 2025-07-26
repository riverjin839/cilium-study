#!/usr/bin/env python3
"""
Kubernetes Lab Environment Generator v2
실습 환경 배포 파일 작성을 자동화하는 Python 스크립트

=== Version 2 Changes ===
- Worker Node Join 방식 개선: SSH 기반 → 설정 파일 기반
- kubeadm-join-worker-config.yaml 파일 추가
- k8s-w.sh 스크립트 간소화 및 안정성 향상
- Vagrantfile에 worker node용 설정 파일 복사 로직 추가
- kubeadm v1beta4 API 사용으로 업데이트
- 보안 및 안정성 개선 (SSH 의존성 제거)
"""

import os
import argparse
import yaml
from pathlib import Path
from datetime import datetime


class K8sLabGenerator:
    def __init__(self, config=None):
        """Initialize with default configuration"""
        self.config = config or {
            'k8s_version': '1.33.2-1.1',
            'containerd_version': '1.7.27-1',
            'cilium_version': '1.17.6',
            'worker_nodes': 2,
            'box_image': 'bento/ubuntu-24.04',
            'box_version': '202502.21.0',
            'lab_name': 'Cilium-Lab',
            'network_prefix': '192.168.10',
            'control_plane_ip': '192.168.10.100',
            'pod_cidr': '172.20.0.0/16'
        }
        
    def generate_vagrantfile(self):
        """Generate Vagrantfile"""
        k8s_version = self.config['k8s_version']
        containerd_version = self.config['containerd_version']
        cilium_version = self.config['cilium_version']
        worker_nodes = self.config['worker_nodes']
        box_image = self.config['box_image']
        box_version = self.config['box_version']
        lab_name = self.config['lab_name']
        control_plane_ip = self.config['control_plane_ip']
        network_prefix = self.config['network_prefix']
        
        vagrantfile_content = f'''# Variables
K8SV = '{k8s_version}' # Kubernetes Version : apt list -a kubelet , ex) 1.32.5-1.1
CONTAINERDV = '{containerd_version}' # Containerd Version : apt list -a containerd.io , ex) 1.6.33-1
CILIUMV = '{cilium_version}' # Cilium CNI Version : https://github.com/cilium/cilium/tags
N = {worker_nodes} # max number of worker nodes

# Base Image  https://portal.cloud.hashicorp.com/vagrant/discover/bento/ubuntu-24.04
BOX_IMAGE = "{box_image}"
BOX_VERSION = "{box_version}"

Vagrant.configure("2") do |config|
#-ControlPlane Node
    config.vm.define "k8s-ctr" do |subconfig|
      subconfig.vm.box = BOX_IMAGE
      
      subconfig.vm.box_version = BOX_VERSION
      subconfig.vm.provider "virtualbox" do |vb|
        vb.customize ["modifyvm", :id, "--groups", "/{lab_name}"]
        vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
        vb.name = "k8s-ctr"
        vb.cpus = 2
        vb.memory = 2048
        vb.linked_clone = true
      end
      subconfig.vm.host_name = "k8s-ctr"
      subconfig.vm.network "private_network", ip: "{control_plane_ip}"
      subconfig.vm.network "forwarded_port", guest: 22, host: 60000, auto_correct: true, id: "ssh"
      subconfig.vm.synced_folder "./", "/vagrant", disabled: true
      subconfig.vm.provision "shell", path: "init_cfg.sh", args: [ K8SV, CONTAINERDV ]
      subconfig.vm.provision "shell", path: "k8s-ctr.sh", args: [ N, CILIUMV ]
    end

#-Worker Nodes Subnet1
  (1..N).each do |i|
    config.vm.define "k8s-w#{{i}}" do |subconfig|
      subconfig.vm.box = BOX_IMAGE
      subconfig.vm.box_version = BOX_VERSION
      subconfig.vm.provider "virtualbox" do |vb|
        vb.customize ["modifyvm", :id, "--groups", "/{lab_name}"]
        vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
        vb.name = "k8s-w#{{i}}"
        vb.cpus = 2
        vb.memory = 1536
        vb.linked_clone = true
      end
      subconfig.vm.host_name = "k8s-w#{{i}}"
      subconfig.vm.network "private_network", ip: "{network_prefix}.10#{{i}}"
      subconfig.vm.network "forwarded_port", guest: 22, host: "6000#{{i}}", auto_correct: true, id: "ssh"
      subconfig.vm.synced_folder "./", "/vagrant", disabled: true
      subconfig.vm.provision "file", source: "kubeadm-join-worker-config.yaml", destination: "/tmp/kubeadm-join-worker-config.yaml"
      subconfig.vm.provision "shell", inline: "sudo mv /tmp/kubeadm-join-worker-config.yaml /root/kubeadm-join-worker-config.yaml"
      subconfig.vm.provision "shell", path: "init_cfg.sh", args: [ K8SV, CONTAINERDV]
      subconfig.vm.provision "shell", path: "k8s-w.sh"
    end
  end

end
'''
        return vagrantfile_content

    def generate_init_cfg_script(self):
        """Generate init_cfg.sh script"""
        script_content = '''#!/usr/bin/env bash

echo ">>>> Initial Config Start <<<<"

echo "[TASK 1] Setting Profile & Bashrc"
echo 'alias vi=vim' >> /etc/profile
echo "sudo su -" >> /home/vagrant/.bashrc
ln -sf /usr/share/zoneinfo/Asia/Seoul /etc/localtime # Change Timezone


echo "[TASK 2] Disable AppArmor"
systemctl stop ufw && systemctl disable ufw >/dev/null 2>&1
systemctl stop apparmor && systemctl disable apparmor >/dev/null 2>&1


echo "[TASK 3] Disable and turn off SWAP"
swapoff -a && sed -i '/swap/s/^/#/' /etc/fstab


echo "[TASK 4] Install Packages"
apt update -qq >/dev/null 2>&1
apt-get install apt-transport-https ca-certificates curl gpg -y -qq >/dev/null 2>&1

# Download the public signing key for the Kubernetes package repositories.
mkdir -p -m 755 /etc/apt/keyrings
K8SMMV=$(echo $1 | sed -En 's/^([0-9]+\\.[0-9]+)\\..*/\\1/p')
curl -fsSL https://pkgs.k8s.io/core:/stable:/v$K8SMMV/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v$K8SMMV/deb/ /" >> /etc/apt/sources.list.d/kubernetes.list
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# packets traversing the bridge are processed by iptables for filtering
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.d/k8s.conf

# enable br_netfilter for iptables 
modprobe br_netfilter
modprobe overlay
echo "br_netfilter" >> /etc/modules-load.d/k8s.conf
echo "overlay" >> /etc/modules-load.d/k8s.conf


echo "[TASK 5] Install Kubernetes components (kubeadm, kubelet and kubectl)"
# Update the apt package index, install kubelet, kubeadm and kubectl, and pin their version
apt update >/dev/null 2>&1

# apt list -a kubelet ; apt list -a containerd.io
apt-get install -y kubelet=$1 kubectl=$1 kubeadm=$1 containerd.io=$2 >/dev/null 2>&1
apt-mark hold kubelet kubeadm kubectl >/dev/null 2>&1

# containerd configure to default and cgroup managed by systemd
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml

# avoid WARN&ERRO(default endpoints) when crictl run  
cat <<EOF > /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
EOF

# ready to install for k8s 
systemctl restart containerd && systemctl enable containerd
systemctl enable --now kubelet


echo "[TASK 6] Install Packages & Helm"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y bridge-utils sshpass net-tools conntrack ngrep tcpdump ipset arping wireguard jq tree bash-completion unzip kubecolor termshark >/dev/null 2>&1
curl -s https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash >/dev/null 2>&1


echo ">>>> Initial Config End <<<<"
'''
        return script_content

    def generate_k8s_ctr_script(self):
        """Generate k8s-ctr.sh script"""
        control_plane_ip = self.config['control_plane_ip']
        pod_cidr = self.config['pod_cidr']
        network_prefix = self.config['network_prefix']
        
        script_content = f'''#!/usr/bin/env bash

echo ">>>> K8S Controlplane config Start <<<<"

echo "[TASK 1] Initial Kubernetes"
curl --silent -o /root/kubeadm-init-ctr-config.yaml https://raw.githubusercontent.com/riverjin839/cilium-study/refs/heads/main/kubeadm-init-ctr-config.yaml
kubeadm init --config="/root/kubeadm-init-ctr-config.yaml" --skip-phases=addon/kube-proxy  >/dev/null 2>&1


echo "[TASK 2] Setting kube config file"
mkdir -p /root/.kube
cp -i /etc/kubernetes/admin.conf /root/.kube/config
chown $(id -u):$(id -g) /root/.kube/config


echo "[TASK 3] Source the completion"
echo 'source <(kubectl completion bash)' >> /etc/profile
echo 'source <(kubeadm completion bash)' >> /etc/profile


echo "[TASK 4] Alias kubectl to k"
echo 'alias k=kubectl' >> /etc/profile
echo 'alias kc=kubecolor' >> /etc/profile
echo 'complete -F __start_kubectl k' >> /etc/profile


echo "[TASK 5] Install Kubectx & Kubens"
git clone https://github.com/ahmetb/kubectx /opt/kubectx >/dev/null 2>&1
ln -s /opt/kubectx/kubens /usr/local/bin/kubens
ln -s /opt/kubectx/kubectx /usr/local/bin/kubectx


echo "[TASK 6] Install Kubeps & Setting PS1"
git clone https://github.com/jonmosco/kube-ps1.git /root/kube-ps1 >/dev/null 2>&1
cat <<"EOT" >> /root/.bash_profile
source /root/kube-ps1/kube-ps1.sh
KUBE_PS1_SYMBOL_ENABLE=true
function get_cluster_short() {{
  echo "$1" | cut -d . -f1
}}
KUBE_PS1_CLUSTER_FUNCTION=get_cluster_short
KUBE_PS1_SUFFIX=') '
PS1='$(kube_ps1)'$PS1
EOT
kubectl config rename-context "kubernetes-admin@kubernetes" "HomeLab" >/dev/null 2>&1


echo "[TASK 7] Install Cilium CNI"
NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\\s)\\d+(\\.\d+){{3}}')
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1
helm repo update >/dev/null 2>&1
helm install cilium cilium/cilium --version $2 --namespace kube-system \\
--set k8sServiceHost={control_plane_ip} --set k8sServicePort=6443 \\
--set ipam.mode="cluster-pool" --set ipam.operator.clusterPoolIPv4PodCIDRList={{"{pod_cidr}"}} --set ipv4NativeRoutingCIDR={pod_cidr} \\
--set routingMode=native --set autoDirectNodeRoutes=true --set endpointRoutes.enabled=true \\
--set kubeProxyReplacement=true --set bpf.masquerade=true --set installNoConntrackIptablesRules=true \\
--set endpointHealthChecking.enabled=false --set healthChecking=false \\
--set hubble.enabled=false --set operator.replicas=1 --set debug.enabled=true >/dev/null 2>&1


echo "[TASK 8] Install Cilium CLI"
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${{CILIUM_CLI_VERSION}}/cilium-linux-${{CLI_ARCH}}.tar.gz >/dev/null 2>&1
tar xzvfC cilium-linux-${{CLI_ARCH}}.tar.gz /usr/local/bin
rm cilium-linux-${{CLI_ARCH}}.tar.gz


echo "[TASK 9] local DNS with hosts file"
echo "{control_plane_ip} k8s-ctr" >> /etc/hosts
for (( i=1; i<=$1; i++  )); do echo "{network_prefix}.10$i k8s-w$i" >> /etc/hosts; done


echo ">>>> K8S Controlplane Config End <<<<"
'''
        return script_content

    def generate_k8s_worker_script(self):
        """Generate k8s-w.sh script - Updated version"""
        script_content = '''#!/usr/bin/env bash

echo ">>>> K8S Node config Start <<<<"

echo "[TASK 1] K8S Controlplane Join"
NODEIP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\\s)\\d+(\\.\d+){3}')
curl --silent -o /root/kubeadm-join-worker-config.yaml https://raw.githubusercontent.com/riverjin839/cilium-study/refs/heads/main/kubeadm-join-worker-config.yaml
sed -i "s/NODE_IP_PLACEHOLDER/${NODEIP}/g" /root/kubeadm-join-worker-config.yaml
kubeadm join --config="/root/kubeadm-join-worker-config.yaml" >/dev/null 2>&1

echo ">>>> K8S Node Config End <<<<"
'''
        return script_content

    def generate_kubeadm_init_config(self):
        """Generate kubeadm-init-ctr-config.yaml"""
        k8s_version = self.config['k8s_version'].split('-')[0]  # Remove the package version suffix
        config_content = f'''apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: {self.config['control_plane_ip']}
  bindPort: 6443
nodeRegistration:
  criSocket: unix:///run/containerd/containerd.sock
  kubeletExtraArgs:
    cgroup-driver: systemd
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: v{k8s_version}
controlPlaneEndpoint: {self.config['control_plane_ip']}:6443
networking:
  serviceSubnet: 10.96.0.0/12
  podSubnet: {self.config['pod_cidr']}
apiServer:
  advertiseAddress: {self.config['control_plane_ip']}
  bindPort: 6443
controllerManager: {{}}
scheduler: {{}}
etcd:
  local:
    dataDir: /var/lib/etcd
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: iptables
'''
        return config_content

    def generate_kubeadm_join_worker_config(self):
        """Generate kubeadm-join-worker-config.yaml"""
        config_content = f'''apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
discovery:
  bootstrapToken:
    token: "123456.1234567890123456"
    apiServerEndpoint: "{self.config['control_plane_ip']}:6443"
    unsafeSkipCAVerification: true
nodeRegistration:
  criSocket: "unix:///run/containerd/containerd.sock"
  kubeletExtraArgs:
    node-ip: "NODE_IP_PLACEHOLDER"
'''
        return config_content

    def generate_config_file(self):
        """Generate configuration file"""
        config_dict = {
            'lab_config': self.config,
            'generated_at': datetime.now().isoformat()
        }
        return yaml.dump(config_dict, default_flow_style=False)

    def save_files(self, output_dir='cilium-lab'):
        """Save all generated files to output directory"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        files = {
            'Vagrantfile': self.generate_vagrantfile(),
            'init_cfg.sh': self.generate_init_cfg_script(),
            'k8s-ctr.sh': self.generate_k8s_ctr_script(),
            'k8s-w.sh': self.generate_k8s_worker_script(),
            'kubeadm-init-ctr-config.yaml': self.generate_kubeadm_init_config(),
            'kubeadm-join-worker-config.yaml': self.generate_kubeadm_join_worker_config(),
            'lab_config.yaml': self.generate_config_file()
        }
        
        for filename, content in files.items():
            file_path = output_path / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Make shell scripts executable
            if filename.endswith('.sh'):
                os.chmod(file_path, 0o755)
                
        print(f"✅ Lab files generated in '{output_dir}' directory")
        return output_path

    def generate_readme(self):
        """Generate README.md with usage instructions"""
        readme_content = f'''# Kubernetes Cilium Lab Environment v2

이 환경은 Kubernetes와 Cilium CNI를 학습하기 위한 실습 환경입니다.

## 🆕 Version 2 주요 변경사항

### Worker Node Join 방식 개선
- **이전 v1**: SSH를 통한 동적 토큰 획득 방식
- **현재 v2**: 설정 파일 기반 join 방식
- **장점**: 
  - 더 안전하고 구조화된 방식
  - SSH 의존성 제거로 네트워크 보안 향상
  - 설정 투명성 및 디버깅 용이성 증대
  - 프로비저닝 안정성 향상

### 추가된 파일
- `kubeadm-join-worker-config.yaml`: Worker Node 전용 join 설정
- kubeadm v1beta4 API 사용

### 기술적 개선사항
- Vagrantfile에 worker node용 설정 파일 자동 복사 로직 추가
- k8s-w.sh 스크립트 간소화 및 오류 처리 개선
- 노드별 IP 주소 자동 설정 (NODE_IP_PLACEHOLDER 치환)

## 환경 구성

- **Control Plane**: 1대 (k8s-ctr)
- **Worker Nodes**: {self.config['worker_nodes']}대 (k8s-w1, k8s-w2, ...)
- **Kubernetes Version**: {self.config['k8s_version']}
- **Containerd Version**: {self.config['containerd_version']}
- **Cilium Version**: {self.config['cilium_version']}
- **Network**: {self.config['network_prefix']}.0/24

## 사용 방법

1. **환경 배포**
   ```bash
   vagrant up
   ```

2. **Control Plane 접속**
   ```bash
   vagrant ssh k8s-ctr
   ```

3. **기본 정보 확인**
   ```bash
   # 호스트 정보
   cat /etc/hosts
   
   # 워커 노드 접속 테스트
   sshpass -p 'vagrant' ssh -o StrictHostKeyChecking=no vagrant@k8s-w1 hostname
   sshpass -p 'vagrant' ssh -o StrictHostKeyChecking=no vagrant@k8s-w2 hostname
   
   # 네트워크 인터페이스 확인
   ifconfig | grep -iEA1 'eth[0-9]:'
   
   # 클러스터 정보 확인
   kubectl cluster-info
   kubectl get node -owide
   kubectl get pod -A -owide
   ```

4. **Cilium 상태 확인**
   ```bash
   cilium status
   cilium config view
   kubectl get ciliumendpoints -A
   ```

5. **환경 정리**
   ```bash
   vagrant destroy -f
   ```

## 파일 구성

- `Vagrantfile`: 가상머신 정의 및 프로비저닝 설정
- `init_cfg.sh`: 기본 시스템 설정 및 Kubernetes 구성요소 설치
- `k8s-ctr.sh`: Control Plane 초기화 및 Cilium CNI 설치
- `k8s-w.sh`: Worker Node를 클러스터에 조인 ⭐ **v2에서 개선됨**
- `kubeadm-init-ctr-config.yaml`: kubeadm 초기화 설정
- `kubeadm-join-worker-config.yaml`: Worker Node 조인 설정 ⭐ **v2에서 새로 추가**
- `lab_config.yaml`: 실습 환경 설정 정보

## 🔧 트러블슈팅

### Worker Node Join 실패 시
```bash
# 각 워커노드에서 수동으로 설정 파일 생성
vagrant ssh k8s-w1
sudo cat > /root/kubeadm-join-worker-config.yaml << 'EOF'
apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
discovery:
  bootstrapToken:
    token: "123456.1234567890123456"
    apiServerEndpoint: "{self.config['control_plane_ip']}:6443"
    unsafeSkipCAVerification: true
nodeRegistration:
  criSocket: "unix:///run/containerd/containerd.sock"
  kubeletExtraArgs:
    node-ip: "NODE_IP_PLACEHOLDER"
EOF

# 스크립트 재실행
sudo /vagrant/k8s-w.sh
```

## 모니터링 명령어

```bash
# Cilium 모니터링
kubectl exec -n kube-system -c cilium-agent -it ds/cilium -- cilium-dbg monitor

# 드롭된 패킷만 모니터링
kubectl exec -n kube-system -c cilium-agent -it ds/cilium -- cilium-dbg monitor --type drop

# Layer 7 트래픽 모니터링
kubectl exec -n kube-system -c cilium-agent -it ds/cilium -- cilium-dbg monitor -v --type l7
```

## ⚠️ 보안 주의사항

현재 설정에서는 고정 토큰(`123456.1234567890123456`)과 `unsafeSkipCAVerification: true`를 사용합니다. 
이는 실습 환경용이며, **실제 프로덕션 환경에서는 다음을 반드시 적용**해야 합니다:
- 동적으로 생성된 보안 토큰 사용
- CA 인증서 검증 활성화
- 적절한 RBAC 및 네트워크 정책 적용

## 📋 변경 이력

### v2 (Current)
- Worker Node join 방식을 설정 파일 기반으로 개선
- kubeadm v1beta4 API 적용
- 프로비저닝 안정성 및 보안 향상

### v1 (Previous)
- SSH 기반 토큰 획득 방식 사용
- 네트워크 의존성이 높은 구조

---
Generated by Kubernetes Lab Generator v2 on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
'''
        return readme_content


def main():
    parser = argparse.ArgumentParser(
        description='Kubernetes 실습 환경 배포 파일 생성기',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                                    # 기본 설정으로 생성
  %(prog)s -w 3 -o my-lab                     # 워커 노드 3개, my-lab 디렉터리에 생성
  %(prog)s -k 1.32.5-1.1 -c 1.6.33-1         # 특정 버전 지정
  %(prog)s --config lab.yaml                  # 설정 파일 사용
        '''
    )
    
    parser.add_argument('-w', '--workers', type=int, default=2,
                       help='워커 노드 수 (기본값: 2)')
    parser.add_argument('-k', '--k8s-version', type=str, default='1.33.2-1.1',
                       help='Kubernetes 버전 (기본값: 1.33.2-1.1)')
    parser.add_argument('-c', '--containerd-version', type=str, default='1.7.27-1',
                       help='Containerd 버전 (기본값: 1.7.27-1)')
    parser.add_argument('--cilium-version', type=str, default='1.17.6',
                       help='Cilium 버전 (기본값: 1.17.6)')
    parser.add_argument('-o', '--output', type=str, default='cilium-lab',
                       help='출력 디렉터리 (기본값: cilium-lab)')
    parser.add_argument('--config', type=str,
                       help='설정 파일 경로 (YAML 형식)')
    parser.add_argument('--lab-name', type=str, default='Cilium-Lab',
                       help='실습 환경 이름 (기본값: Cilium-Lab)')
    parser.add_argument('--network-prefix', type=str, default='192.168.10',
                       help='네트워크 프리픽스 (기본값: 192.168.10)')
    
    args = parser.parse_args()
    
    # Load configuration from file if provided
    config = None
    if args.config:
        try:
            with open(args.config, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
                config = config_data.get('lab_config', {})
        except FileNotFoundError:
            print(f"❌ 설정 파일을 찾을 수 없습니다: {args.config}")
            return 1
        except yaml.YAMLError as e:
            print(f"❌ 설정 파일 파싱 오류: {e}")
            return 1
    
    # Override with command line arguments
    if not config:
        config = {}
    
    config.update({
        'worker_nodes': args.workers,
        'k8s_version': args.k8s_version,
        'containerd_version': args.containerd_version,
        'cilium_version': args.cilium_version,
        'lab_name': args.lab_name,
        'network_prefix': args.network_prefix,
        'control_plane_ip': f"{args.network_prefix}.100"
    })
    
    # Generate lab environment
    generator = K8sLabGenerator(config)
    output_path = generator.save_files(args.output)
    
    # Generate README
    readme_path = output_path / 'README.md'
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(generator.generate_readme())
    
    print(f"""
🚀 Kubernetes Cilium Lab 환경 v2가 생성되었습니다!

📁 출력 디렉터리: {args.output}
🖥️  워커 노드 수: {config['worker_nodes']}
🐳 Kubernetes: {config['k8s_version']}
🔧 Containerd: {config['containerd_version']}
🌐 Cilium: {config['cilium_version']}

🆕 v2 주요 개선사항:
✅ Worker Node join 방식을 설정 파일 기반으로 개선
✅ SSH 의존성 제거로 안정성 향상
✅ kubeadm v1beta4 API 적용
✅ 프로비저닝 과정 최적화

다음 명령어로 환경을 시작하세요:
  cd {args.output}
  vagrant up

Control Plane 접속:
  vagrant ssh k8s-ctr

자세한 사용법과 변경사항은 README.md를 참고하세요.
    """)
    
    return 0


if __name__ == '__main__':
    exit(main())
