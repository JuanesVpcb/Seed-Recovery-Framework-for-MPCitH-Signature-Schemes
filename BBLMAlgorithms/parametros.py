import pprint
# W
beta = [0.03, 0.05, 0.10, 0.15, 0.20, 0.25]
W = [128, 192, 256]

W_escogido = W[1]

w  = [2**i for i in range(2, 5)] #min(5, int.bit_length(W_escogido))+1)]  # w = [4, 6, 8, 10, 12, 14, 16, 18]

w_escogido = w[1]

e = {2**k for k in range(1, int.bit_length(W_escogido // w_escogido) + 1) if ((2**k) * w_escogido) != 0 and W_escogido % ((2**k) * w_escogido) == 0} #[2**i for i in range(1, log2(W_escogido/w_escogido))]

e_escogido = min(e)

m = {2**k for k in range(1, min(5, e_escogido*w_escogido)+1)}

print(f"W = {sorted(W)}")
print(f"w = {sorted(w)}")
print(f"e = {sorted(e)}")
print(f"m = {sorted(m)}")
print(f"beta = {sorted(beta)}")
total = []
for W in W:
    for w_val in w:
        for eta in e:
            m = {2**k for k in range(1, min(10, eta*w_val)+1)}
            for mu in m:
                if W % (eta * w_val) == 0:
                    for beta_val in beta:
                        if W // (eta * w_val) >= 2:
                            total.append((W, w_val, eta, mu, beta_val))

pprint.pprint(len(total))

            
