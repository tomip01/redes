import matplotlib.pyplot as plt
import numpy as np
from scapy.all import *

mapeoProtocoloNombre = {
    2048: 'IPv4',
    2054: 'ARP',
    34525: 'IPv6',
    34999: 'OUI'
}

def rename(S):
    S2 = {}
    for (cast,code) in S:
        S2[(cast,mapeoProtocoloNombre[code])] = S[(cast,code)]
    return S2

def graficoBarras(probabilidadesEventos, informacionesEventos):
    valoresRenombrados = rename(probabilidadesEventos)
    simbolos = []
    for key in valoresRenombrados:
        simbolos.append(f"{key}")
    probabilidades = list(probabilidadesEventos.values())
    informaciones = list(informacionesEventos.values())
    
    width = 0.4
    
    x = np.arange(len(valoresRenombrados))
    
    plt.bar(x-0.2, probabilidades, width=width, tick_label=simbolos, label='probabilidades')
    plt.bar(x+0.2, informaciones, width=width, tick_label=simbolos, label='informacion')
    plt.legend()
    plt.show()
    
def unicastVsBroadCast(paquetes):
    broadcast = 0.0
    unicast = 0.0
    n = 0.0
    for paquete in paquetes:
        if paquete.haslayer(Ether):
            if paquete[Ether].dst=="ff:ff:ff:ff:ff:ff":
                broadcast += 1
            else:
                unicast += 1
        n += 1
                
    resultado = (unicast/n, broadcast/n)
    return resultado

def porcentajeDeCadaProtocolo(paquetes):
    cantidadPorProtocolo = {}
    n = 0.0
    for paquete in paquetes:
        if paquete.haslayer(Ether):
            protocolo = paquete[Ether].type
            if mapeoProtocoloNombre[protocolo] not in cantidadPorProtocolo:
                cantidadPorProtocolo[mapeoProtocoloNombre[protocolo]] = 0.0
            cantidadPorProtocolo[mapeoProtocoloNombre[protocolo]] += 1
            
        n += 1
    
    for protocolo in cantidadPorProtocolo:
        cantidadPorProtocolo[protocolo] /= n
        
    return cantidadPorProtocolo

def informacionVsEntropia(informacionPorSimbolos, entropia):
    valoresRenombrados = rename(informacionPorSimbolos)
    simbolos = []
    for key in valoresRenombrados:
        simbolos.append(f"{key}")
    informaciones = list(informacionPorSimbolos.values())
    
    n = len(informacionPorSimbolos)
    x = range(n)
    
    plt.bar(x, informaciones, tick_label=simbolos, width=0.4, label='probabilidades')
    plt.plot(x,[entropia] * n, label='entropia', color='r')
    plt.legend()
    plt.show()