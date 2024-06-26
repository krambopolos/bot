#!/bin/bash

# Mise à jour des paquets existants
sudo apt-get update

# Installation des prérequis
sudo apt-get install -y ca-certificates curl

# Création du répertoire keyrings si nécessaire
sudo install -m 0755 -d /etc/apt/keyrings

# Téléchargement de la clé GPG de Docker
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc

# Modification des permissions pour la clé
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Ajout du dépôt Docker aux sources de APT
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Mise à jour des paquets après ajout du nouveau dépôt
sudo apt-get update

# Installation de Docker et des plugins nécessaires
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

sudo systemctl start docker

# Télécharger la dernière version de Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.5.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# Rendre le binaire exécutable
sudo chmod +x /usr/local/bin/docker-compose

# Vérifier l'installation
docker-compose --version

sudo chmod -R /home/ubuntu/scans

sudo chmod -R /home/ubuntu/scans/*

cd /home/ubuntu/scans

sudo docker-compose up --build -d