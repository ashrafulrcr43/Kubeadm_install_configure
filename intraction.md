# Making AWS 3 instance , 1 master, 2 Worker ubuntu 24
## Create 3 instance in AWS using bash file 
1. create .pem file
2. create_3_instance.sh 
<pre>
  #!/bin/bash
set -e

# Configuration
AWS_PROFILE="default"
REGION="ap-northeast-3"
IMAGE_ID="ami-0fe4e90accd5cc34a"
INSTANCE_TYPE="t3.medium"
DISK_SIZE=20
DISK_TYPE="gp3"
KEY_NAME="kuadmin_aws"  #
MY_IP=$(curl -s https://checkip.amazonaws.com)/32

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# AWS CLI common options
AWS_OPTS="--region $REGION --profile $AWS_PROFILE --output text"

# Logging functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }


# Get default VPC and subnet
get_default_vpc() {
    log_info "Getting default VPC using profile: $AWS_PROFILE..."
    DEFAULT_VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' $AWS_OPTS)
    if [ "$DEFAULT_VPC" == "None" ]; then
        log_error "No default VPC found in region $REGION"
    fi
    log_info "Default VPC: $DEFAULT_VPC"
}

get_default_subnet() {
    log_info "Getting default subnet..."
    DEFAULT_SUBNET=$(aws ec2 describe-subnets \
        --filters Name=vpc-id,Values=$DEFAULT_VPC Name=default-for-az,Values=true \
        --query 'Subnets[0].SubnetId' \
        $AWS_OPTS)
    if [ "$DEFAULT_SUBNET" == "None" ]; then
        log_error "No default subnet found in VPC $DEFAULT_VPC"
    fi
    
    SUBNET_CIDR=$(aws ec2 describe-subnets \
        --subnet-ids $DEFAULT_SUBNET \
        --query 'Subnets[0].CidrBlock' \
        $AWS_OPTS)
    log_info "Default Subnet: $DEFAULT_SUBNET (CIDR: $SUBNET_CIDR)"
}

# Find available private IPs
find_available_ips() {
    log_info "Finding available private IPs..."
    
    NETWORK_PREFIX=$(echo $SUBNET_CIDR | cut -d'.' -f1-3)
    START_IP=30
    IPS=()
    
    for i in {0..2}; do
        TARGET_IP="$NETWORK_PREFIX.$((START_IP + i))"
        
        IP_IN_USE=$(aws ec2 describe-instances \
            --filters Name=private-ip-address,Values=$TARGET_IP \
            --query 'Reservations[].Instances[].InstanceId' \
            $AWS_OPTS)
        
        if [ -z "$IP_IN_USE" ]; then
            IPS+=($TARGET_IP)
            log_info "Available IP: $TARGET_IP"
        else
            log_warning "IP $TARGET_IP is in use by instance $IP_IN_USE"
        fi
    done
    
    if [ ${#IPS[@]} -lt 3 ]; then
        log_error "Not enough available IPs found. Needed 3, found ${#IPS[@]}"
    fi
    
    CONTROL_PLANE_IP=${IPS[0]}
    WORKER1_IP=${IPS[1]}
    WORKER2_IP=${IPS[2]}
}

# Create security group
create_security_group() {
    log_info "Creating security group 'Kube-ADM'..."
    
    EXISTING_SG=$(aws ec2 describe-security-groups \
        --filters Name=group-name,Values=Kube-ADM Name=vpc-id,Values=$DEFAULT_VPC \
        --query 'SecurityGroups[0].GroupId' \
        $AWS_OPTS)
    
    if [ "$EXISTING_SG" != "None" ]; then
        log_info "Security group 'Kube-ADM' already exists: $EXISTING_SG"
        SG_ID=$EXISTING_SG
    else
        SG_ID=$(aws ec2 create-security-group \
            --group-name "Kube-ADM" \
            --description "Kubernetes ADM Security Group" \
            --vpc-id $DEFAULT_VPC \
            --query 'GroupId' \
            $AWS_OPTS)
        log_info "Created security group: $SG_ID"
    fi
    
    log_info "Configuring security group rules..."
    
    aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 22 \
        --cidr $MY_IP \
        $AWS_OPTS 2>/dev/null || log_warning "SSH rule may already exist"
    
    aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 6443 \
        --cidr 0.0.0.0/0 \
        $AWS_OPTS 2>/dev/null || log_warning "API Server rule may already exist"
    
    aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 2379-2380 \
        --source-group $SG_ID \
        $AWS_OPTS 2>/dev/null || log_warning "etcd rule may already exist"
    
    aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 10250 \
        --source-group $SG_ID \
        $AWS_OPTS 2>/dev/null || log_warning "Kubelet rule may already exist"
    
    aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 10259 \
        --source-group $SG_ID \
        $AWS_OPTS 2>/dev/null || log_warning "Scheduler rule may already exist"
    
    aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 10257 \
        --source-group $SG_ID \
        $AWS_OPTS 2>/dev/null || log_warning "Controller rule may already exist"
    
    aws ec2 authorize-security-group-ingress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 30000-32767 \
        --cidr 0.0.0.0/0 \
        $AWS_OPTS 2>/dev/null || log_warning "NodePort rule may already exist"
}

# Create instances
create_instances() {
    log_info "Creating Kubernetes instances..."
    
    INSTANCE_SPECS=(
        "k8s-control-plane:$CONTROL_PLANE_IP"
        "k8s-worker-1:$WORKER1_IP"
        "k8s-worker-2:$WORKER2_IP"
    )
    
    INSTANCE_JSON="["
    
    for spec in "${INSTANCE_SPECS[@]}"; do
        IFS=':' read -r INSTANCE_NAME PRIVATE_IP <<< "$spec"
        
        log_info "Creating $INSTANCE_NAME with IP $PRIVATE_IP..."
        
        INSTANCE_ID=$(aws ec2 run-instances \
            --image-id $IMAGE_ID \
            --instance-type $INSTANCE_TYPE \
            --key-name $KEY_NAME \
            --security-group-ids $SG_ID \
            --subnet-id $DEFAULT_SUBNET \
            --private-ip-address $PRIVATE_IP \
            --associate-public-ip-address \
            --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":$DISK_SIZE,\"VolumeType\":\"$DISK_TYPE\"}}]" \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME}]" \
            --query 'Instances[0].InstanceId' \
            $AWS_OPTS)
        
        if [ "$INSTANCE_JSON" != "[" ]; then
            INSTANCE_JSON+=","
        fi
        
        INSTANCE_JSON+="{\"name\":\"$INSTANCE_NAME\",\"id\":\"$INSTANCE_ID\",\"private_ip\":\"$PRIVATE_IP\"}"
        
        log_info "Created $INSTANCE_NAME: $INSTANCE_ID"
    done
    
    INSTANCE_JSON+="]"
    
    echo -e "\n${GREEN}Instance Creation Summary:${NC}"
    echo $INSTANCE_JSON | python3 -m json.tool 2>/dev/null || echo $INSTANCE_JSON
}

# Check AWS profile
check_aws_profile() {
    log_info "Checking AWS profile: $AWS_PROFILE"
    
    if ! aws sts get-caller-identity --profile $AWS_PROFILE &> /dev/null; then
        log_error "AWS profile '$AWS_PROFILE' not configured or invalid. Available profiles:"
        aws configure list-profiles 2>/dev/null || log_error "No AWS profiles found. Run 'aws configure' first."
        exit 1
    fi
    
    log_info "AWS profile '$AWS_PROFILE' is valid"
    log_info "Account details:"
    aws sts get-caller-identity --profile $AWS_PROFILE --output text | awk '{print "Account:", $1; print "User ID:", $2; print "ARN:", $3}'
}

# Main execution
main() {
    log_info "Starting Kubernetes cluster provisioning..."
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install it first."
    fi
    
    # Check AWS profile
    check_aws_profile
    
    get_default_vpc
    get_default_subnet
    find_available_ips
    create_security_group
    create_instances
    
    log_info "Kubernetes cluster provisioning completed successfully using profile: $AWS_PROFILE!"
    log_info "Wait a few minutes for instances to initialize, then SSH using:"
    log_info "ssh -i your-key.pem ubuntu@<public-ip>"
}

main "$@"
</pre>
# Login Master node on termanl or putty
Run bellow Comment
<pre>
  Execute below commands 

	1. System Prerequisite Commands:

		swapoff -a
		sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
		echo 'overlay' | tee /etc/modules-load.d/containerd.conf
		echo 'br_netfilter' | tee -a /etc/modules-load.d/containerd.conf
		modprobe overlay
		modprobe br_netfilter
		echo 'net.bridge.bridge-nf-call-iptables = 1' | tee /etc/sysctl.d/99-kubernetes-cri.conf
		echo 'net.ipv4.ip_forward = 1' | tee -a /etc/sysctl.d/99-kubernetes-cri.conf
		echo 'net.bridge.bridge-nf-call-ip6tables = 1' | tee -a /etc/sysctl.d/99-kubernetes-cri.conf
		sysctl --system

	# change this with your ec2-instance ips
		echo "
		172.31.0.30 k8s-control-plane
		172.31.0.31 k8s-worker-1
		172.31.0.32 k8s-worker-2" | sudo tee -a /etc/hosts


	2. Package Management Commands:

		apt-get update
		apt-get install -y containerd
		mkdir -p /etc/containerd
		containerd config default | tee /etc/containerd/config.toml


	3. Containerd Configuration:

		sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml
		systemctl restart containerd
		systemctl enable containerd
		systemctl status containerd --no-pager -l



	4. Kubernetes Repository Setup:

		apt-get install -y apt-transport-https ca-certificates curl gpg
		mkdir -p /etc/apt/keyrings
		curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
		echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list
		apt-get update


	5. Kubernetes Installation:

		apt-get install -y kubelet kubeadm kubectl
		apt-mark hold kubelet kubeadm kubectl

	6. Verification Commands:

		containerd --version
		kubelet --version
		kubectl version --client
		kubeadm version
		which kubectl kubelet kubeadm
		ls -la /usr/bin/kubectl /usr/bin/kubelet /usr/bin/kubeadm


	7. Initialize the cluster using the master's IP:

		sudo kubeadm init --apiserver-advertise-address=172.31.16.30 --pod-network-cidr=192.168.0.0/16 --ignore-preflight-errors=NumCPU,Mem

	************************* Save this for Node joining *********************
	kubeadm join 172.31.0.30:6443 --token 1b84a2.08oyi0ae63vgzxwb \
			--discovery-token-ca-cert-hash sha256:aa7a18d96856fc3d7ab8c6a902ccf734cf2bc38008b7a5af0887c234f0eced9a
			
			
			
	8. Configure kubectl for your user:

		mkdir -p $HOME/.kube && sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config && sudo chown $(id -u):$(id -g) $HOME/.kube/config

	9. Install the Calico Network Add-on:

		kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/tigera-operator.yaml
		kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/custom-resources.yaml

  10.  Check nodes 
  kubectl get nodes

  
</pre>
# worker server login 
<pre>
	 Execute below sh script 
	all_script_kubeadm.sh

	#!/bin/bash
# Kubernetes Installation Script with Error Handling and Logging
set -e

# Configuration
LOG_FILE="/var/log/kubernetes-install.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
CONTAINERD_CONFIG="/etc/containerd/config.toml"
KUBERNETES_KEYRING="/etc/apt/keyrings/kubernetes-apt-keyring.gpg"
KUBERNETES_LIST="/etc/apt/sources.list.d/kubernetes.list"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$TIMESTAMP [INFO] $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$TIMESTAMP [WARN] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$TIMESTAMP [ERROR] $1" >> "$LOG_FILE"
    exit 1
}

# Function to check command success
check_success() {
    if [ $? -eq 0 ]; then
        log_info "$1 completed successfully"
    else
        log_error "$1 failed. Check $LOG_FILE for details."
    fi
}

# Function to run command with error handling
run_cmd() {
    local cmd="$1"
    local description="$2"
    
    log_info "Starting: $description"
    echo "$TIMESTAMP [CMD] $cmd" >> "$LOG_FILE"
    
    # Execute command and capture both stdout and stderr
    if eval "$cmd" >> "$LOG_FILE" 2>&1; then
        log_info "$description completed successfully"
    else
        log_error "$description failed. Exit code: $?"
    fi
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root. Please use sudo."
    fi
}

# Function to check internet connectivity
check_internet() {
    log_info "Checking internet connectivity..."
    if ! ping -c 1 -W 2 google.com >/dev/null 2>&1; then
        if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
            log_warning "No internet connectivity detected. Some operations may fail."
        fi
    fi
}

# Function to setup system prerequisites
setup_prerequisites() {
    log_info "Setting up system prerequisites for Kubernetes"
    
    # Disable swap
    run_cmd "swapoff -a" "Disable swap"
    run_cmd "sed -i '/ swap / s/^\\(.*\\)$/#\\1/g' /etc/fstab" "Comment out swap in fstab"
    
    # Load kernel modules
    run_cmd "echo 'overlay' | tee /etc/modules-load.d/containerd.conf" "Add overlay module to modules-load"
    run_cmd "echo 'br_netfilter' | tee -a /etc/modules-load.d/containerd.conf" "Add br_netfilter module to modules-load"
    run_cmd "modprobe overlay" "Load overlay kernel module"
    run_cmd "modprobe br_netfilter" "Load br_netfilter kernel module"
    
    # Configure sysctl for Kubernetes networking
    run_cmd "echo 'net.bridge.bridge-nf-call-iptables = 1' | tee /etc/sysctl.d/99-kubernetes-cri.conf" "Configure iptables bridge calls"
    run_cmd "echo 'net.ipv4.ip_forward = 1' | tee -a /etc/sysctl.d/99-kubernetes-cri.conf" "Configure IP forwarding"
    run_cmd "echo 'net.bridge.bridge-nf-call-ip6tables = 1' | tee -a /etc/sysctl.d/99-kubernetes-cri.conf" "Configure ip6tables bridge calls"
    
    # Apply sysctl params
    run_cmd "sysctl --system" "Apply sysctl parameters"
}

# Main installation function
install_kubernetes() {
    log_info "Starting Kubernetes installation process"
    log_info "Log file: $LOG_FILE"
    
    # Check prerequisites
    check_root
    check_internet
    
    # Setup system prerequisites
    setup_prerequisites
    
    # Update package lists
    run_cmd "apt-get update" "Update package lists"
    
    # Install containerd
    run_cmd "apt-get install -y containerd" "Install containerd"
    
    # Create containerd directory if it doesn't exist
    if [ ! -d "/etc/containerd" ]; then
        run_cmd "mkdir -p /etc/containerd" "Create containerd config directory"
    fi
    
    # Generate containerd default config
    if command -v containerd >/dev/null 2>&1; then
        run_cmd "containerd config default | tee $CONTAINERD_CONFIG" "Generate containerd default configuration"
    else
        log_error "containerd command not found after installation"
    fi
    
    # Enable systemd cgroups
    if [ -f "$CONTAINERD_CONFIG" ]; then
        run_cmd "sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' $CONTAINERD_CONFIG" "Enable systemd cgroups in containerd config"
    else
        log_error "Containerd config file not found: $CONTAINERD_CONFIG"
    fi
    
    # Restart and enable containerd
    run_cmd "systemctl restart containerd" "Restart containerd service"
    run_cmd "systemctl enable containerd" "Enable containerd service"
    run_cmd "systemctl status containerd --no-pager -l" "Check containerd status"
    
    # Install additional packages
    run_cmd "apt-get install -y apt-transport-https ca-certificates curl gpg" "Install required packages"
    
    # Create keyrings directory
    if [ ! -d "/etc/apt/keyrings" ]; then
        run_cmd "mkdir -p /etc/apt/keyrings" "Create apt keyrings directory"
    fi
    
    # Add Kubernetes GPG key
    run_cmd "curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | gpg --dearmor -o $KUBERNETES_KEYRING" "Add Kubernetes GPG key"
    
    # Add Kubernetes repository
    run_cmd "echo 'deb [signed-by=$KUBERNETES_KEYRING] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' | tee $KUBERNETES_LIST" "Add Kubernetes repository"
    
    # Update package lists again
    run_cmd "apt-get update" "Update package lists with Kubernetes repo"
    
    # Install Kubernetes components
    run_cmd "apt-get install -y kubelet kubeadm kubectl" "Install Kubernetes components (kubelet, kubeadm, kubectl)"
    
    # Hold packages to prevent accidental upgrades
    run_cmd "apt-mark hold kubelet kubeadm kubectl" "Hold Kubernetes packages to prevent auto-upgrade"
    
    # Verify installations (using compatible commands)
    run_cmd "containerd --version" "Verify containerd installation"
    run_cmd "kubelet --version" "Verify kubelet installation"
    run_cmd "kubectl version --client" "Verify kubectl installation"  # Fixed: removed --short flag
    run_cmd "kubeadm version" "Verify kubeadm installation"
    
    # Additional verification
    run_cmd "which kubectl kubelet kubeadm" "Verify binary locations"
    run_cmd "ls -la /usr/bin/kubectl /usr/bin/kubelet /usr/bin/kubeadm" "Verify binary permissions"
    
    log_info "Kubernetes installation completed successfully!"
    log_info "Next steps:"
    log_info "1. Initialize cluster with: kubeadm init"
    log_info "2. Set up kubectl config: mkdir -p \$HOME/.kube && cp -i /etc/kubernetes/admin.conf \$HOME/.kube/config"
    log_info "3. Install network plugin (Calico, Flannel, etc.)"
}

# Cleanup function (optional)
cleanup() {
    log_info "Cleaning up temporary files..."
    # Add any cleanup operations here if needed
}

# Trap signals for cleanup
trap cleanup EXIT INT TERM

# Main execution
main() {
    log_info "=== Kubernetes Installation Script Started ==="
    
    # Check if log directory exists
    if [ ! -d "/var/log" ]; then
        mkdir -p /var/log
    fi
    
    # Create log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    # Run installation
    install_kubernetes
    
    log_info "=== Kubernetes Installation Script Completed ==="
    echo -e "${GREEN}Installation completed successfully! Check $LOG_FILE for details.${NC}"
}

# Run main function
main "$@"
	
</pre>

# join worker server 
<pre>
	you get link from master server 
	
kubeadm join 172.31.16.30:6443 --token 582izh.q31vbe6d3m996ram \
        --discovery-token-ca-cert-hash sha256:a6dd02b76686fbd4d8d9cf3167822167bda7d7dd4ceda9e9046899d7ad5daad6
	
</pre>

# check the master server nodes
<pre>
	kubectl get nodes
</pre>
# Deploy ngnix image to master server 
<pre>
	kubectl create deployment nginx --image=sarowaralam/sarowar-nginx --replicas=3
	kubectl expose deployment nginx --port=80 --type=NodePort
</pre>
# Check pods, Deployment,services
<pre>
kubectl get pods
kubectl get deployment
kubectl get services
	
</pre>
# Laravel Project Deployment 
<pre>
	project Requirement:
	docker pull ashraful90/salesinventory

run

docker run -d -p 8000:8000 --name salesinventory ashraful90/salesinventory

docker ps

docker exec -it be53e8ebb6db bash

ls -la /var/www/html

6 .Enter source and run

cd /var/www/html

php artisan serve --host=0.0.0.0 --port=8000
</pre>
	
# Deployment bellow 

<pre>
	kubectl create deployment salesinventory --image=ashraful90/salesinventory --replicas=3
	kubectl expose deployment salesinventory --port=8000 --type=NodePort

	kubectl get svc
	# Collect Svc PortNumber 
	
	kubectl get pods
	kubectl exec -it <pod-name> -- bash
	php artisan serve
</pre>
	
# Trobuleshout 
<pre>
	kubectl describe node ip-172-31-16-30

	# pods Delete 
	kubectl delete pod nginx-55d5796cf7-d82vs
	
</pre>

# kubeadm reset 
<pre>
	sudo kubeadm reset -f

sudo rm -rf /etc/cni/net.d
sudo ip link delete cni0 2>/dev/null
sudo ip link delete flannel.1 2>/dev/null
sudo ip link delete weave 2>/dev/null

sudo apt-get purge -y kubeadm kubectl kubelet kubernetes-cni kube* 
sudo apt-get autoremove -y

sudo rm -rf ~/.kube
sudo rm -rf /var/lib/etcd
sudo rm -rf /var/lib/kubelet
sudo rm -rf /etc/kubernetes

</pre>
# Problem Ip Change Trobuleshoot
<pre>
	kubectl config view --minify | grep server:
	kubectl config get-clusters
	** my putput = kubernetes
	kubectl config set-cluster <cluster-name> --server=https://192.168.10.169:6443

</pre>
# Trouleshot Connection Refues
<pre>
	ls -l ~/.kube/config
   ubectl config get-contexts
  kubectl config current-context
</pre>
