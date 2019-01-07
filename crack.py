import sys
import crypt
import time
hash_names = {"md5":'$1', 'sha256':'$5','sha512':'$6'}


#d_args = {'-f':None, '-h': None, '-w':None, '-word':None, '-salt':None, '-type':None}
d_args = {}


usage = """\n\t------ ATTACK MOD --------
\t-h      single hash or a file to crack
\t-w      the wordlist for the attack\n

\t------ HASH MOD --------\n
\t--word  a word to hash
\t--salt  the salt for the hash
\t--type  hash type [md5, sha256, sha512]
"""



def rd_args():
    args = sys.argv
    i = args[0]
    args.remove(i)
    found_hash = False


    if len(args) > 1:
        # attack mode section
        if '-h' in args and '-w' in args:
            for i in args:
                if '-' in i:
                    d_args[i] = args[args.index(i)+1]
            return d_args
        # Hash mod section
        if '--word' in args and '--salt' in args and '--type':
                for i in args:
                    if '-' in i:
                        d_args[i] = args[args.index(i)+1]
                return d_args , found_hash

    else:
        print(usage)
        exit(0)

def hash_(word,salt):
    return crypt.crypt(word,salt)

def attack_mod(arg):

    try:
        wordlist = arg['-w']
    except:
        print('wordlist is missing')
        exit(0)
    try:
        hash_file = arg['-h']
    except:
        print('-h is missing')
        exit(0)
    #hash_arg = "odin:$6$Xb1zLYWB$jt2o.Vy2PHK/m7SLjE44ythZkwGOq4G2i71yNE4mH9/S5H3x6Sl5jefd.gYDdpVR6fLHFstjH5/tYM2tFRVrM/:17748:0:99999:7:::"

    hash_file = open(hash_file,'r')
    for hash_arg in hash_file.readlines():
        hash_arg = hash_arg.split('\n')[0]
        target_ = hash_arg.split(':')

        target_user = target_[0]

        target_hash = target_[1]

        salt_num = target_hash.rfind("$")

        target_salt = target_hash[:salt_num]

        with open(wordlist,'r') as wdlist:
            for line in wdlist.readlines():
                ripped = line.split('\n')[0]
                word_to_hash = hash_(ripped,target_salt)
                if word_to_hash == target_hash:
                    print('-'*50)
                    print("\n[*] Username: {}\n\n[*] Hash: {}\n\n[+] Cracked Hash: {}\n".format(target_user,target_hash,ripped))
                    print('-'*50)
                    time.sleep(1)
                    break
                else:
                    continue



def hash_mod(args):
    try:
        word_ = args['--word']
    except Exception as e:

        print('[-] parameter --word is missing')
        exit(0)
    try:
        salt_ = args['--salt']
    except:
        print('[-] parameter --salt is missing')
        exit(0)
    try:
        type_ = args['--type']
    except:
        print('[-] parameter --type is missing')
        exit(0)
    salt_n_type = str(hash_names[type_]+"$"+salt_)

    hashed_ = hash_(word_,salt_n_type)
    print('[*] word: {}\tsalt: {}\ttype: {}\n'.format(word_,salt_,type_))
    print('[+] Hashed: {}'.format(hashed_))



if __name__ == '__main__':
    attack_mod(rd_args())
