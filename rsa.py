# RON-SHAMIR-ADLEMAN
# GENERATE PUBLIC AND PRIVATE KEY PAIRS
import random

class rsa:
    lowPrimeList = list()
    MAX_SIZE = 3572
    KEY_SIZE = 1024
    ## GIVES AN ERROR RATE OF 1/2^128
    ## VIABLE ENOUGH FOR COMMERCIAL APPLICATIONS
    MILLER_TEST=32 
    
    ## PRIVATE
    _PRIVATE_KEY=[]
    _PUBLIC_KEY=[]
    _PHI=0
    
    def __init__(self):
        pass
    
    @staticmethod
    def egcd(a, n):
        r0, r1 = max(a, n), min(a, n)
        s0, s1 = 1, 0
        t0, t1 = 0, 1
        
        while r1 != 0:
            q = r0 // r1
            r = r0 - q * r1
            s = s0 - q * s1
            t = t0 - q * t1
            r0 = r1
            r1 = r
            t0 = t1
            t1 = t
            s0 = s1
            s1 = s
        return r0, t0, s0
    
    @staticmethod
    def invmod(a, n):
        _, x, _ = rsa.egcd(a, n)
        return x % n
    
    @staticmethod
    def nBitRandom(n):
        return random.randrange(2**(n-1)+1, 2**n-1)
    
    @staticmethod
    def power(b, e, m):
        res = 1
        b = b%m
        while e > 0:
            if e % 2 == 1:
                res = (res * b) % m
            e = e // 2
            b = (b * b) % m
            
        return res
    
    def genLowPrime(self):
        ## GENERATING FIRST FEW HUNDRED PRIMES
        ## FOR LOW-LEVEL PRIMALITY TEST
        spf = [0]* self.MAX_SIZE
        isPrime = [True]*self.MAX_SIZE
        isPrime[0], isPrime[1] = False, False
        
        for i in range(2, self.MAX_SIZE):
            if isPrime[i]:
                self.lowPrimeList.append(i)
                spf[i] = i
            for j in self.lowPrimeList:
                if j <= spf[i] and i * j < self.MAX_SIZE:
                    isPrime[i*j] = False
                    spf[i*j]=j
                else:
                    break
        
    def getLowLevelPrime(self):
        ## GENERATE A PRIME OF SAID SIZE THAT
        ## PASSES THE LOW LEVEL PRIMALITY TEST
        while True:
            randPrime = rsa.nBitRandom(self.KEY_SIZE)
            flag = True
            for p in self.lowPrimeList:
                if p*p < randPrime:
                    if randPrime % p == 0:
                        flag = False
                        break
                else:
                    break
            if flag:
                break
        return randPrime
    
    def millerTest(self, d, n, r):
        ## RABIN MILLER TEST
        a = random.randrange(2, n-2)
        x = rsa.power(a, d, n)
        if x == 1 or x == n-1:
            return True
        for _ in range(r):
            x = (x*x) % n
            d = d*2
            if x == 1:
                return False
            if x == n-1:
                return True
            
    def checkHighLevelPrime(self, n):
        ## HIGH LEVEL PRIMALITY TEST
        ## MULTIPLE RABIN MILLER TESTS
        ## TO REDUCE ERROR RATE
        d = n-1
        r = 0
        while d % 2 == 0:
            d = d / 2
            r += 1
        for _ in range(self.MILLER_TEST):
            if self.millerTest(d, n, r) == False:
                print(False)
                return False
        return True
    
    def genRSAPrime(self):
        while True:
            p = self.getLowLevelPrime()
            if self.checkHighLevelPrime(p):
                return p
    
    def generatePublicKey(self):
        x = self.genRSAPrime()
        y = self.genRSAPrime()
        
        while x == y:
            x = self.genRSAPrime()
            y = self.genRSAPrime()
            
        n = x * y
        phi = (x-1)*(y-1)
        self._PHI = phi
        ## e HAVING A SHORT BIT-LENGTH
        ## AND SMALL HAMMING CODE
        ## RESULTS IN EFFICIENT ENCRYPTION
        e = 2**16 + 1
        self._PUBLIC_KEY=[e, n]
        
    def generatePrivateKey(self):
        e, n = self._PUBLIC_KEY
        d = rsa.egcd(e, self._PHI)
        self._PRIVATE_KEY = [d, n]
        
    def generateKeys(self):
        self.generatePublicKey()
        self.generatePrivateKey()
        return self._PUBLIC_KEY
    
        
encoder = rsa()
print(encoder.generateKeys())
    