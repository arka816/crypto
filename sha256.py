# SECURE HASH ALGORITHM - 2 FAMILY
# SHA 256
# PUBLICATION- 2001
# NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY

class sha256:
    K=[
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 
      ]
    H=[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    mod=2**32
    msg=""
    blocks=[]
    
    def __init__(self, msg):
        self.msg=sha256.toBinString(msg)
        
    @staticmethod
    def RotR(x, n):
        X='{0:b}'.format(x).zfill(32)
        X=X[(32-n):] + X[:(32-n)]
        ret=int(X, base=2)
        return ret
        
    @staticmethod
    def Ch(x, y, z):
        ## choice
        ret=(x&y)^(~x&z)
        return '{0:b}'.format(ret)
    
    @staticmethod
    def Maj(x, y, z):
        ## majority
        ret=(x&y)^(y&z)^(x&z)
        return '{0:b}'.format(ret)
    
    @staticmethod
    def Σ0(x):
        x1=sha256.RotR(x, 2)
        x2=sha256.RotR(x, 13)
        x3=sha256.RotR(x, 22)
        ret=x1^x2^x3
        return '{0:b}'.format(ret)
    
    @staticmethod
    def Σ1(x):
        x1=sha256.RotR(x, 6)
        x2=sha256.RotR(x, 11)
        x3=sha256.RotR(x, 25)
        ret=x1^x2^x3
        return '{0:b}'.format(ret)
    
    @staticmethod
    def σ0(X):
        x=int(X, base=2)
        x1=sha256.RotR(x, 7)
        x2=sha256.RotR(x, 18)
        ret=x1^x2^(x>>3)
        return '{0:b}'.format(ret)
    
    @staticmethod
    def σ1(X):
        x=int(X, base=2)
        x1=sha256.RotR(x, 17)
        x2=sha256.RotR(x, 19)
        ret=x1^x2^(x>>10)
        return '{0:b}'.format(ret)
    
    @staticmethod
    def toBinString(s):
        ret=''.join(format(x, 'b').zfill(8) for x in bytearray(s, 'utf-8'))
        return ret
    
    def pad(self, msg):
        ## padding
        l=len(msg)
        k=((447-l)%512)
        msg+='1'+(k*'0')+'{0:b}'.format(l).zfill(64)
        return msg
    
    def block_decomposition(self, block):
        ## decomposing a block of size 512 bits
        ## into 64 32 bit words
        words=[block[i: i+32] for i in range(0, 512, 32)]
        for i in range(16, 64, 1):
            s1=int(sha256.σ1(words[i-2]), base=2)
            w1=int(words[i-7], base=2)
            s0=int(sha256.σ0(words[i-15]), base=2)
            w2=int(words[i-16], base=2)
            #print(s1, w1, s0, w2)
            val=(s1+w1+s0+w2)%self.mod
            word='{0:b}'.format(val).zfill(32)
            words.append(word)
            
        #print(words[:16])
        #print(words[16:])
        return words
    
        
    def hash(self):
        self.msg=self.pad(self.msg)
        self.blocks=[self.msg[i:i+512] for i in range(0, len(self.msg), 512)]
        for block in self.blocks:
            ## construct the 64 blocks Wi 
            ## from message blocks M
            ## words contains those 64 blocks
            words=self.block_decomposition(block)
            ## set a, b, c, ... as elements of the H array
            a, b, c, d, e, f, g, h = self.H
            ## 64 salting rounds
            for i in range(64):
                T1=(h + int(sha256.Σ1(e), base=2)+int(sha256.Ch(e, f, g), base=2)+self.K[i]+int(words[i], base=2))%self.mod
                T2=(int(sha256.Σ0(a), base=2) + int(sha256.Maj(a, b, c), base=2))%self.mod
                h=g
                g=f
                f=e
                e=(d+T1)%self.mod
                d=c
                c=b
                b=a
                a=(T1+T2)%self.mod
                
            ## add a, b, c, ... to H
            self.H=[
                        (self.H[0]+a)%self.mod, 
                        (self.H[1]+b)%self.mod,
                        (self.H[2]+c)%self.mod,
                        (self.H[3]+d)%self.mod,
                        (self.H[4]+e)%self.mod,
                        (self.H[5]+f)%self.mod,
                        (self.H[6]+g)%self.mod,
                        (self.H[7]+h)%self.mod,
                    ]
        hashString=""
        for h in self.H:
            hashString+='{0:x}'.format(h).zfill(8)
        return hashString
   
s="arka"
hasher=sha256(s)
print("original message:", s)
print("hashed value:", hasher.hash())
