## Network Security Project ##
### Fatema Tuj Johora | Mashroor Hasan Bhuiyan ###
1. install conda
```
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
chmod +x Miniconda3-latest-Linux-x86_64.sh
./Miniconda3-latest-Linux-x86_64.sh
source ~/miniconda3/bin/activate
conda update -n base -c defaults conda -y
conda --version
```
2. create conda env.
```
conda create --name f25cn
conda activate f25cn
conda env create -f environment.yml
```
3. to run the files, simply do ``python3 <filename>``