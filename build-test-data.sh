#!/bin/bash

TD=/opt/testdata

rm -rf /opt/testdata

# oneuser 84
# twouser 85
# threeuser 86
# oneusernew 87
# twousernew 88
# threeusernew 89

# --uidpair 84:87 --uidpair 85:88 --uidpair 86:89

sudo useradd one
sudo useradd oneuser
sudo useradd twouser
sudo useradd threeuser
sudo useradd oneusernew
sudo useradd twousernew
sudo useradd threeusernew

sudo mkdir -p $TD
sudo mkdir -p $TD/shared/
sudo chown oneuser $TD/shared/

sudo mkdir -p $TD/one
echo "one data" | sudo tee -a $TD/one/onefile
echo "one shared data" | sudo tee -a $TD/shared/one
sudo chown -R oneuser $TD/one/
sudo chmod -R u=rwx,g=rwx $TD/one/
sudo chown oneuser $TD/shared/one
sudo setfacl -m u:oneuser:r $TD/shared/
sudo setfacl -d -m u:oneuser:r $TD/shared/

sudo mkdir -p $TD/two
echo "two data" | sudo tee -a $TD/two/twofile
echo "two shared data" | sudo tee -a $TD/shared/two
sudo chown -R twouser $TD/two/
sudo chmod -R u=rwx,g=rwx $TD/two/
sudo chown twouser $TD/shared/two
sudo setfacl -m u:twouser:r $TD/shared/
sudo setfacl -d -m u:twouser:r $TD/shared/

sudo mkdir -p $TD/three
echo "three data" | sudo tee -a $TD/three/threefile
echo "three shared data" | sudo tee -a $TD/shared/three
sudo chown -R threeuser $TD/three/
sudo chmod -R u=rwx,g=rwx $TD/three/
sudo chown threeuser $TD/shared/three
sudo setfacl -m u:threeuser:r $TD/shared/
sudo setfacl -d -m u:threeuser:r $TD/shared/

rm -f $TD/one/shared-one
sudo ln -s $TD/shared/one $TD/one/shared-one
