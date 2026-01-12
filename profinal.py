import numpy as np
import os
import matplotlib.pyplot as plt
from tkinter import filedialog, Tk, Label, Button, Toplevel, Frame, Text, END, Scrollbar
from datetime import datetime

# le Style  
plt.style.use('ggplot') 

#  EXPORTATION DES DONNÉES
def exporter_fichiers(donnees_par_ip):
    # Export CSV
    try:
        with open("analyse_completeB7.csv", "w", encoding="utf-8") as f:
            f.write("IP_SOURCE;PORT_SOURCE;IP_DESTINATION;PORT_DESTINATION;PROTOCOLE;FLAGS;TAILLE;LATENCE\n")
            for ip_src, paquets in donnees_par_ip.items():
                for p in paquets:
                    lat = p.get('latence', 0)  # <-- 0 si pas de latence
                    f.write(f"{ip_src};{p['port_src']};{p['dest']};{p['port_dest']};{p['proto']};{p['flag']};{p['len']};{lat}\n")
        print(" Fichier CSV 'aymen_analyse_complete.csv' généré.")
    except Exception as e: 
        print(f"Erreur export CSV: {e}")

    # Export Markdown
    try:
        with open("aymen.md", "w", encoding="utf-8") as f:
            f.write("#  rapport Analyse Réseau par fichier texte - Expert\n\n")
            f.write("Ce rapport contient l'inventaire complet des flux détectés dans le fichier dump.\n\n")
            f.write("| Source (Port Src) | Destination (Port Dest) | Protocole | Flags | Taille |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- |\n")
            for ip_src, paquets in donnees_par_ip.items():
                for p in paquets:
                    f.write(f"| {ip_src} ({p['port_src']}) | {p['dest']} ({p['port_dest']}) | {p['proto']} | `{p['flag']}` | {p['len']} |\n")
        print("Fichier Markdown 'aymen.md' généré avec succès.")
    except Exception as e: 
        print(f"Erreur export Markdown: {e}")

# ANALYSE DES TENTATIVES DE CONNEXIONS
def ouvrir_analyse_cyber(ip, liste_paquets, stats_latence):
    win_cyber = Toplevel()
    win_cyber.title(f"ANALYSE DES TENTATIVES DE CONNEXIONS : {ip}")
    win_cyber.geometry("800x800")
    win_cyber.configure(bg="#1e272e")

    Label(win_cyber, text="ANALYSE DES TENTATIVES DE CONNEXIONS", font=("Arial", 14, "bold"), bg="#1e272e", fg="#00d8d6", pady=20).pack()
    
    txt = Text(win_cyber, bg="#2f3640", fg="white", font=("Consolas", 10), padx=15, pady=15)
    txt.pack(expand=True, fill="both", padx=20, pady=10)

    mes_connexions = [s for s in stats_latence if s['src'] == ip]
    nb_reussites = len(mes_connexions)
    nb_syn = sum(1 for p in liste_paquets if p['flag'] == "S")
    avg_latence = sum(c['ms'] for c in mes_connexions) / nb_reussites if nb_reussites > 0 else 0

    txt.insert(END, "==================================================\n")
    txt.insert(END, f"BILAN DE CONNEXION POUR : {ip}\n")
    txt.insert(END, "==================================================\n\n")
    txt.insert(END, f"• Tentatives envoyées (SYN)     : {nb_syn}\n")
    txt.insert(END, f"• Connexions réussies (SYN-ACK) : {nb_reussites}\n")
    txt.insert(END, f"• TEMPS MOYEN DE RÉUSSITE       : {avg_latence:.4f} ms\n\n", "bolt")

    if nb_syn > 0:
        taux = (nb_reussites / nb_syn) * 100
        txt.insert(END, f" Taux de succès : {taux:.1f}%\n")

    txt.insert(END, "\n DÉTAILS DES CONNEXIONS RÉUSSIES (RTT) :\n")
    txt.insert(END, "-"*50 + "\n")
    for c in mes_connexions[:20]:
        txt.insert(END, f"{c['dst']:<20} | {c['ms']:.4f} ms\n")

    txt.tag_config("bolt", foreground="#fbc531", font=("Consolas", 12, "bold"))
    txt.config(state="disabled")
    Button(win_cyber, text="FERMER", command=win_cyber.destroy, bg="#e84118", fg="white").pack(pady=10)

# FENÊTRE DE DÉTAILS
def ouvrir_fenetre_details(ip, liste_paquets, stats_latence):
    win_detail = Toplevel()
    win_detail.title(f"Détails IP : {ip}")
    win_detail.geometry("900x980")
    win_detail.configure(bg="#ffffff")

    nb_total_ip = len(liste_paquets)
    tailles = [int(p['len']) if p['len'].isdigit() else 0 for p in liste_paquets]
    vol_total = sum(tailles)
    taille_moy = vol_total / nb_total_ip if nb_total_ip > 0 else 0
    taille_max = max(tailles) if tailles else 0
    
    ports_src_count, ports_dest_count, proto_count, destinations, flags_count = {}, {}, {}, {}, {}
    for p in liste_paquets:
        ports_src_count[p['port_src']] = ports_src_count.get(p['port_src'], 0) + 1
        ports_dest_count[p['port_dest']] = ports_dest_count.get(p['port_dest'], 0) + 1
        proto_count[p['proto']] = proto_count.get(p['proto'], 0) + 1
        destinations[p['dest']] = destinations.get(p['dest'], 0) + 1
        f = p['flag'] if p['flag'] else "N/A"
        flags_count[f] = flags_count.get(f, 0) + 1

    header = Frame(win_detail, bg="#f8f9fa", pady=20, borderwidth=1, relief="solid")
    header.pack(fill="x")
    Label(header, text=f"DOSSIER FORENSIC : {ip}", font=("Arial", 14, "bold"), bg="#f8f9fa").pack()
    Label(header, text=f"Volume total : {nb_total_ip} paquets envoyés", font=("Arial", 10), bg="#f8f9fa", fg="#d63031").pack()

    body = Frame(win_detail, bg="#ffffff", pady=10)
    body.pack(fill="both", expand=True, padx=40)

    Label(body, text="ANALYSE DES TAILLES (OCTETS)", font=("Arial", 11, "bold"), bg="#ffffff", fg="#27ae60").pack(anchor="w", pady=(10,5))
    Label(body, text=f" • Total : {vol_total} octets | Moyenne : {taille_moy:.2f} octets | Max : {taille_max} octets", font=("Consolas", 10), bg="#ffffff").pack(anchor="w", padx=20)

    Label(body, text="\n COMPARAISON DES PORTS (SRC VS DEST)", font=("Arial", 11, "bold"), bg="#ffffff", fg="#0984e3").pack(anchor="w", pady=(5,5))
    sub_frame = Frame(body, bg="#f1f2f6", padx=10, pady=10)
    sub_frame.pack(fill="x")
    top_src = sorted(ports_src_count.items(), key=lambda x: x[1], reverse=True)[:5]
    top_dst = sorted(ports_dest_count.items(), key=lambda x: x[1], reverse=True)[:5]
    for i in range(max(len(top_src), len(top_dst))):
        src_text = f"P.Source {top_src[i][0]} : {top_src[i][1]} pqs" if i < len(top_src) else ""
        dst_text = f"P.Dest {top_dst[i][0]} : {top_dst[i][1]} pqs" if i < len(top_dst) else ""
        Label(sub_frame, text=f"{src_text:<25} | {dst_text}", font=("Consolas", 9), bg="#f1f2f6").pack(anchor="w")

    Label(body, text="\n PROTOCOLES ET SERVICES", font=("Arial", 11, "bold"), bg="#ffffff", fg="#6c5ce7").pack(anchor="w")
    for pr, c in sorted(proto_count.items(), key=lambda x: x[1], reverse=True):
        Label(body, text=f" • {pr} : {c} paquets", font=("Consolas", 10), bg="#ffffff").pack(anchor="w", padx=20)

    Label(body, text="\n CIBLES IP", font=("Arial", 11, "bold"), bg="#ffffff", fg="#2d3436").pack(anchor="w")
    for d, c in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:5]:
        Label(body, text=f" • {d} ————> {c} paquets", font=("Consolas", 10), bg="#ffffff").pack(anchor="w", padx=20)

    Label(body, text="\n SIGNATURES (FLAGS TCP)", font=("Arial", 11, "bold"), bg="#ffffff", fg="#2d3436").pack(anchor="w")
    for f, count in flags_count.items():
        Label(body, text=f" • Flag [{f}] : {count} paquets", font=("Consolas", 10), bg="#ffffff").pack(anchor="w", padx=20)

    Button(win_detail, text=" ANALYSE DES TENTATIVES DE CONNEXIONS", 
           command=lambda: ouvrir_analyse_cyber(ip, liste_paquets, stats_latence), 
           bg="#1e272e", fg="#00d8d6", font=("Arial", 10, "bold"), padx=20).pack(pady=10)
    
    Button(win_detail, text="RETOUR", command=win_detail.destroy, bg="#636e72", fg="white", font=("Arial", 10, "bold"), padx=25).pack(pady=10)

# LOGIQUE D'EXTRACTION 
def lancer_analyse(chemin_fichier):
    if not chemin_fichier: return
    donnees_par_ip, suivi_syn, stats_latence = {}, {}, []
    with open(chemin_fichier, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if any(key in line for key in [" IP ", " ARP ", " ICMP "]):
                parts = line.split(" ")
                try:
                    t_obj = datetime.strptime(parts[0], "%H:%M:%S.%f")
                    proto = "Autre"
                    if "ssh" in line or ".22 " in line: proto = "SSH"
                    elif "http" in line or ".80 " in line: proto = "HTTP"
                    elif "https" in line or ".443 " in line: proto = "HTTPS"
                    elif "domain" in line or ".53 " in line: proto = "DNS"
                    elif "TCP" in line or "Flags" in line: proto = "TCP"
                    elif "UDP" in line: proto = "UDP"
                    elif "ICMP" in line: proto = "ICMP"
                    elif "ARP" in line: proto = "ARP"

                    if " IP " in line:
                        src_raw = parts[2].split(".")
                        p_src, ip_src = src_raw[-1], ".".join(src_raw[:-1])
                        dest_raw = parts[4].rstrip(":").split(".")
                        p_dest, ip_dest = dest_raw[-1], ".".join(dest_raw[:-1])
                        flag = line.split("[")[1].split("]")[0] if "[" in line else ""
                        
                        # CALCUL LATENCE SYN -> SYN-ACK
                        latence = 0
                        if flag == "S": 
                            suivi_syn[(ip_src, p_src, ip_dest, p_dest)] = t_obj
                        elif flag == "S." and (ip_dest, p_dest, ip_src, p_src) in suivi_syn:
                            heure_syn = suivi_syn.pop((ip_dest, p_dest, ip_src, p_src))
                            latence = (t_obj - heure_syn).total_seconds() * 1000
                            stats_latence.append({'src': ip_dest, 'dst': ip_src, 'ms': latence})

                    else:
                        ip_src, p_src, ip_dest, p_dest, flag = parts[1], "N/A", parts[3], "N/A", ""

                    length = line.split("length ")[1].strip() if "length " in line else "0"
                    if ip_src not in donnees_par_ip: donnees_par_ip[ip_src] = []
                    donnees_par_ip[ip_src].append({
                        'dest': ip_dest, 'port_src': p_src, 'port_dest': p_dest, 
                        'proto': proto, 'flag': flag, 'len': length, 'latence': latence
                    })
                except: continue

    exporter_fichiers(donnees_par_ip)
    
    ips_f = sorted(donnees_par_ip.keys(), key=lambda k: len(donnees_par_ip[k]))
    paquets_f = [len(donnees_par_ip[ip]) for ip in ips_f]
    fig, ax = plt.subplots(figsize=(10, 6), facecolor='#ffffff')
    ax.barh(ips_f, paquets_f, color="#0984e3")
    ax.set_title("TRAFIC TOTAL PAR IP SOURCE", fontsize=12, fontweight='bold')
    fig.canvas.mpl_connect('button_press_event', 
                           lambda e: (ouvrir_fenetre_details(ips_f[int(round(e.ydata))], 
                                                             donnees_par_ip[ips_f[int(round(e.ydata))]], 
                                                             stats_latence) if e.inaxes else None))
    plt.tight_layout()
    plt.show()

# ACCUEIL
def interface_accueil():
    root = Tk()
    root.title("Analyseur pro de aymen boumliki")
    root.geometry("350x250")
    root.configure(bg="#ffffff")
    Label(root, text="NETWORK ANALYZER", font=("Arial", 12, "bold"), bg="#ffffff").pack(pady=40)
    Button(root, text="CHARGER UN DUMP", 
           command=lambda: [root.destroy(), lancer_analyse(filedialog.askopenfilename())], 
           bg="#0984e3", fg="white", padx=10, pady=5).pack()
    root.mainloop()

if __name__ == "__main__":
    interface_accueil()
