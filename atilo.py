#! /usr/bin/env python3

# Copyright 2017-2020 by YadominJinta. All rights reserved.
# https://github.com/YadominJinta/atilo has info about the project.
# https://github.com/YadominJinta/atilo/blob/master/CONTRIBUTORS.md Thank you for help.

import os
import tarfile
import requests
import json
import hashlib
import io
import sys
from tqdm import tqdm
from prettytable import PrettyTable
from bs4 import BeautifulSoup

home = os.getenv('HOME')
atilo_home = home + '/.atilo/'
atilo_tmp = atilo_home + 'tmp/'
atilo_config = atilo_home + 'local.json'
atilo_version = "2.1.0"
CN = True


def getLang(cn, en):
    print(cn if CN else en)


def getLang2(cn, en):
    return cn if CN else en


requestUrl = getLang2('https://cdn.jsdelivr.net/gh/YadominJinta/atilo@master/src/list_cn.json',
                      'https://cdn.jsdelivr.net/gh/YadominJinta/atilo@master/src/list.json')


def check_dir():
    if not os.path.isdir(atilo_home):
        os.mkdir(atilo_home)
    if not os.path.isdir(atilo_tmp):
        os.mkdir(atilo_tmp)


def check_arch():
    arch = os.uname().machine
    if arch == 'aarch64' or 'armv8' in arch:
        arch = 'aarch64'
    elif arch == 'x86_64':
        arch = 'amd64'
    elif '86' in arch:
        arch = 'i386'
    elif 'arm' in arch:
        arch = 'armhf'
    else:
        getLang('手机架构不受支持', 'Your device''s arch are not in supoport')
        exit(1)
    return arch


def load_local():
    if not os.path.isfile(atilo_config):
        with open(atilo_config, 'w') as f:
            arch = check_arch()
            data = {
                'config': {
                    'arch': arch,
                    'version': atilo_version
                }
            }
            json.dump(data, indent=4, fp=f)
    with open(atilo_config, 'r') as f:
        config = json.load(f)
    return config


def get_list():
    try:
        r = requests.get(requestUrl)
    except requests.exceptions.ConnectionError as e:
        getLang('无法连接到GitHub，可能需要代理', 'Can''t connect to GitHub. A Proxy may be needed.')
        exit(1)
    if not r.status_code == 200:
        getLang('无法获取镜像列表', 'Can''t get image list.')
        exit(1)
    return r.json()


def show_list():
    lists = get_list()
    config = load_local()
    table = PrettyTable()
    arch = check_arch()
    table.field_names = getLang2(["名称", "版本", "已安装", "可安装"],
                                 ["Name", "Version", "Installed", "Installable"])
    for i in lists.get('linux'):
        name = i
        infos = lists.get(name)
        version = infos.get('version')
        installed = name in config.keys()
        installable = arch in infos.keys()
        table.add_row([name, version, installed, installable])
    print(table.get_string())


def pull_image(distro):
    arch = check_arch()
    lists = get_list()
    config = load_local()
    distro_tmp = atilo_tmp + distro
    if distro in config.keys():
        getLang(distro + '已被安装', 'You have installed ' + distro)
        exit(1)
    if distro not in lists.keys():
        getLang('未找到' + distro, distro + ' not found')
        exit(1)
    infos = lists.get(distro)
    if arch not in infos.keys():
        getLang(distro + '不支持该架构', distro + ' not suppoer your arch')
        exit(1)
    if CN and infos.get('lxc') == True:
        time_stamp = get_lxc(infos.get(arch))
        url = infos.get(arch) + time_stamp + '/rootfs.tar.xz'
    else:
        url = infos.get(arch)
    if os.path.isfile(distro_tmp):
        getLang(distro + '已缓存', distro + ' already downloaded')
        getLang('跳过下载', 'Skipping download')
    else:
        getLang('拉取镜像中', 'Pulling image')
        r = requests.get(url, stream=True)
        if not r.status_code == 200:
            getLang('无法拉取镜像', 'Can''t pull the image')
            getLang('网络错误', 'Network Error')
            exit(1)
        total_size = int(r.headers.get('Content-Length'))
        block_size = io.DEFAULT_BUFFER_SIZE
        t = tqdm(total=total_size, unit='iB', unit_scale=True)
        with open(atilo_tmp + distro, 'wb') as f:
            for chunk in r.iter_content(block_size):
                t.update(len(chunk))
                f.write(chunk)
        r.close()
        t.close()
    checkMethod = infos.get('check')
    if checkMethod == 'ubuntu':
        check_url = 'https://partner-images.canonical.com/core/' + infos.get('version') + '/current/MD5SUMS'
        check_sum_ubuntu(distro, check_url)
    elif checkMethod == 'lxc':
        check_url = infos.get(arch) + time_stamp + '/SHA256SUMS'
        check_sum(distro=distro, url=check_url, check='sha256')
    elif checkMethod == 'no':
        getLang(distro + '不支持校验', distro + ' has no check method')
        getLang('跳过校验', 'skiping')
    else:
        check_url = url + '.' + checkMethod
        check_sum(distro=distro, url=check_url, check=checkMethod)

    if not infos.get('zip') == 'fedora':
        extract_file(distro, infos.get('zip'))
    else:
        extract_fedora()
    config_image(distro, infos)


def get_lxc(url):
    r = requests.get(url)
    if not r.status_code == 200:
        print('无法获取镜像链接')
        print('正在退出')
        exit(1)
    soup = BeautifulSoup(r.text, 'html.parser')
    urls = soup.find_all('a')
    time_stamp = (urls[-1]).get('title')
    return time_stamp


def remove_image(distro):
    distro_path = atilo_home + distro
    getLang('移除' + distro + '镜像', 'Removing image ' + distro)
    os.system('chmod -R 777 ' + distro_path)
    os.system('rm -rf ' + distro_path)
    config = load_local()
    del config[distro]
    with open(atilo_config, 'w') as f:
        json.dump(config, indent=4, fp=f)


def config_image(distro, infos):
    getLang('配置镜像中', 'Configuring image')
    distro_path = atilo_home + distro
    resolv_conf = distro_path + '/etc/resolv.conf'
    if os.path.exists(resolv_conf):
        os.remove(resolv_conf)
    with open(resolv_conf, 'w') as f:
        f.write('nameserver 1.1.1.1\n')
        f.write('nameserver 8.8.8.8\n')
    config = load_local()
    config.update({distro: infos})
    with open(atilo_config, 'w') as f:
        json.dump(config, indent=4, fp=f)
    getLang('一切完成', 'All done')
    getLang('使用 atilo run ' + distro + ' 来运行', 'Run it with atilo run ' + distro)


def extract_file(distro, zip_m):
    distro_path = atilo_home + distro
    file_path = atilo_tmp + distro
    if os.path.isdir(distro_path):
        os.system('chmod -R 777 ' + distro_path)
        os.system('rm -rf ' + distro_path)

    zip_f = tarfile.open(file_path, 'r:' + zip_m)
    if not os.path.isdir(distro_path):
        os.mkdir(distro_path)
    getLang('解压镜像中', 'Extracting image')
    zip_f.extractall(distro_path, numeric_owner=True)


def extract_fedora():
    file_path = atilo_tmp + 'fedora'
    distro_path = atilo_home + 'fedora'
    getLang('解压镜像中', 'Extracting image')
    zip_f = tarfile.open(file_path)
    for i in zip_f.getnames():
        if 'layer.tar' in i:
            zip_name = i
    zip_f.extract(zip_name, atilo_tmp)
    zip_f.close()
    zip_f = tarfile.open(atilo_tmp + zip_name, 'r')
    if not os.path.isdir(distro_path):
        os.mkdir(distro_path)
    zip_f.extractall(distro_path, numeric_owner=True)


def check_sum(distro, url, check):
    getLang('校验文件完整性', 'Checking file integrity')
    r = requests.get(url)
    file_path = atilo_tmp + distro
    if not r.status_code == 200:
        print(getLang2('无法获取文件校验码，是否继续 [y/N]', 'Can''t get checksum file,are you sure to continue? [y/N]'), end=' ')
        a = ''
        input(a)
        if not a == 'y':
            getLang('正在退出', 'Exiting')
            os.remove(file_path)
            exit(1)
        else:
            return
    sum_calc = hashlib.md5() if check == 'md5' else hashlib.sha256()
    total_size = os.path.getsize(file_path)
    block_size = io.DEFAULT_BUFFER_SIZE
    t = tqdm(total=total_size, unit='iB', unit_scale=True)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            t.update(len(chunk))
            sum_calc.update(chunk)
    t.close()
    f.close()

    if sum_calc.hexdigest() in r.text:
        getLang('文件校验成功', 'Checksum successfully')
        return 0
    else:
        getLang('文件校验失败', 'Checksum error,Removing file')
        getLang('正在退出', 'Exiting')
        os.remove(file_path)
        exit(1)


def check_sum_ubuntu(distro, url):
    r = requests.get(url)
    file_path = atilo_tmp + distro
    if not r.status_code == 200:
        print(getLang2('无法获取文件校验码，是否继续 [y/n]',
                       'Can''t get checksum file,are you sure to continue? [y/n]'), end=' ')
        a = ''
        input(a)
        if not a == 'y':
            getLang('正在退出', 'Exiting')
            os.remove(file_path)
            exit(1)
    sum_calc = hashlib.md5()
    total_size = os.path.getsize(file_path)
    block_size = io.DEFAULT_BUFFER_SIZE
    t = tqdm(total=total_size, unit='iB', unit_scale=True)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            t.update(len(chunk))
            sum_calc.update(chunk)
    t.close()
    f.close()

    if sum_calc.hexdigest() in r.text:
        return 0
    else:
        getLang('文件校验失败', 'Checksum error')
        getLang('正在退出', 'Exiting')
        os.remove(file_path)
        exit(1)


def clean_tmps():
    getLang('正在清除缓存', 'Cleaning temporary files')
    os.system('rm -rf ' + atilo_tmp + '*')


def run_image(arg):
    distro = arg[0]
    config = load_local()
    if not distro in config.keys():
        getLang('未在本地找到' + distro + '镜像', 'You don''t have ' + distro + 'image')
        getLang('请先拉取该镜像', 'Pull it before running it')
        exit(1)
    distro_path = atilo_home + distro
    infos = config.get(distro)
    command = ''
    command += 'proot'
    command += ' --link2symlink'
    command += ' -S '
    command += distro_path
    #   command += ' -b /sdcard'
    #   command += ' -b /system'
    #   command += ' -b /data/data/com.termux/files/home'
    command += ' -w /root'
    command += ' /usr/bin/env -i'
    command += ' HOME=/root'
    command += ' LANG=C.UTF-8'
    command += ' PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin'
    command += ' TERM=xterm-256color'
    command += ' /bin/'
    os.unsetenv('LD_PRELOAD')
    if 'shell' in infos.keys():
        command += infos.get('shell')
    else:
        if CN:
            command += 'bash'
        else:
            with open(distro_path + "/etc/passwd") as f:
                passwd_dict = {}
                for line in f:
                    args = line.split(":")
                    passwd_dict[args[0]] = args[6]

                shell = passwd_dict['root'].strip().split('/')
                if (shell[-1] != '' and len(shell[-1]) != 0):
                    command += shell[-1]
                else:
                    command += 'bash'

    command += ' --login'
    if len(arg) > 1:
        ext_com = ' '.join(arg[1:])
        os.system(command + ' -c ' + ext_com)
    else:
        os.system(command)


def show_help():
    if CN:
        print('Atilo\t\t' + atilo_version)
        print('Usage: atilo [命令] [参数]\n')
        print('Atilo 是一个用来帮助你在termux上安装不同的GNU/Linux发行版的程序\n')
        print('命令:')
        print('images\t\t 列出可用镜像')
        print('remove\t\t 移除本地的镜像')
        print('pull\t\t 拉取远程的镜像')
        print('run\t\t 运行镜像')
        print('clean\t\t 清除缓存')
        print('help\t\t 帮助\n')
    else:
        print('Atilo\t\t' + atilo_version)
        print('Usage: atilo [Command] [Argument]\n')
        print('Atilo is a program to help you install some GNU/Linux distributions on Termux.\n')
        print('Commands:')
        print('images\t\t list available images')
        print('remove\t\t remove installed images')
        print('pull\t\t pulling an image')
        print('run\t\t run an image')
        print('clean\t\t clean tmps')
        print('help\t\t show this help.\n')


if __name__ == "__main__":
    check_dir()
    if len(sys.argv) == 1:
        show_help()
        getLang('请指定一个命令', 'A command is needed.')
        exit(1)
    if sys.argv[1] == 'help':
        show_help()
    elif sys.argv[1] == 'pull':
        if len(sys.argv) < 3:
            getLang('你需要从镜像列表中指定可用镜像', 'You need to specific a image from list.')
            exit(1)
        elif len(sys.argv) > 3:
            getLang('无用参数', 'Too many arguments.')
            exit(1)
        else:
            pull_image(sys.argv[2])
    elif sys.argv[1] == 'images':
        show_list()
    elif sys.argv[1] == 'remove':
        if len(sys.argv) < 3:
            getLang('你需要从镜像列表中指定可用镜像', 'You need to specific a image from list.')
            exit(1)
        elif len(sys.argv) > 3:
            getLang('无用参数', 'Too many arguments.')
            exit(1)
        else:
            remove_image(sys.argv[2])
    elif sys.argv[1] == 'run':
        if len(sys.argv) < 3:
            getLang('你需要从镜像列表中指定可用镜像', 'You need to specific a image from list.')
            exit(1)
        else:
            run_image(sys.argv[2:])
    elif sys.argv[1] == 'clean':
        clean_tmps()
    else:
        getLang('未知命令', 'Unknown command')
        exit(1)
