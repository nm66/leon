#!/bin/python3
# -*- coding: utf-8 -*-

#import de la bibliothèque pour les logs
import logging
from logging.handlers import *
import os
#import de la bibliothèque pour mesurer les temps d'exécution
import time
#import des bibliothèques permettant de passer des arguments
import sys, getopt

#import de la bibliothèque angr
import angr
import claripy
from angr.block import CapstoneInsn, CapstoneBlock
from collections import OrderedDict
#import de la bibliothèque monkeyhex pour afficher les sorties en hexa
import monkeyhex




#définition de la fonction de nop - NMA/usr/bin/env python3
def nothing(state):
    pass

#définition de la classe Programmes qui contiendra les programmes binaires
class Programme:

    def __init__(self, idpgm, adrhook, typepgm, idpgmuseful, regcmp, errorfound):
        # l'id du programme dont on parle
        self.idpgm = idpgm
        # l'adresse du hook (-1 pour le golden run)
        self.adrhook = adrhook
        # le type de classement du programme (useless ou useful)
        self.typepgm = typepgm
        # l'id du programme pour lequel on sort le même résultat (a un sens et est renseigné seulement pour le type useless)
        self.idpgmuseful = idpgmuseful
        # la valeurs des registres pour laquelle on a obtenu un résultat identique avec un
        # autre programme (a un sens et est renseigné seulement pour le type useless)
        self.regcmp = regcmp
        # le flag indiquant si angr a généré une erreur lors du traitement du programme (0 pour faux, 1 pour vrai)
        self.errorfound = errorfound

    def setId(self, idpgm):
        self.idpgm = idpgm
    
    def setHookAddress(self, adrhook):
        self.adrhook = adrhook
    
    def setProgramType(self, typepgm):
        self.pgmtype = typepgm

    def setProgramType(self, idpgmuseful):
        self.idpgmuseful = idpgmuseful

    def setProgramType(self, regcmp):
        self.regcmp = regcmp

    def setProgramType(self, errorfound):
        self.errorfound = errorfound

# Rappel des registres d'un processeur ARM
# R0 - R6  : general purpose
# R7       : syscall number
# R8 - R10 : general purpose
# R11      : Frame pointer (FP) - points to the bottomn of the stack frame. Keeps track of the boundries on the stack
# R12      : Intraprocedural (IP) - intra-procedure call scratch register
# R13      : Stack Pointer (SP) - points on top of the stack. Used for allocating space on the stack
# R14      : Link Register (LR) - receives the return address when BL or BLX instruction is executed
# R15      : Program Counter (PC) - Holds the address of the next instruction to be executed

       
def main(argv):

    

 
    # Nom du programme du programme binaire à analyser
    binaryFile=""
    # Nom de la fonction sur laquelle on veut faire les hooks
    funcName="main"
    limiter = "2"

    # Paramètres : le nom du programme et le nom du point d'entrée du programme 
    try:
        opts, args = getopt.getopt(sys.argv[1:],"b:f:l:",["binary=", "function_name=", "limiter="])
    except getopt.GetoptError:
        print("%s -b <binary_file> [ -f <function_name> ]  [ -l <0 | 1 | 2> ]" % (__file__))
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print("-b <binary> : nom du binaire à analyser")
            print("-f <function_name> : le nom de la fonction sur laquelle ajouter les hooks")
            print("-l <0 | 1| 2> choix de la technique d'exploration avec limiter")
        elif opt in ("-b", "--binary"):
            binaryFile = arg
        elif opt in ("-f", "--function"):
            funcName =arg
        elif opt in ("-l", "--limiter"):
            limiter=arg

    # création d'un formateur qui va ajouter le temps, le niveau
    # de chaque message quand on écrira un message dans le log
    # création de l'objet logger qui va nous servir à écrire dans les logs
    
       # Niveau de log d'angr pour éviter les warnings
       # création de l'objet logger qui va nous servir à écrire dans les logs
    logger = logging.getLogger()
    logFileName =  os.path.basename(binaryFile) + "_" + str(os.getpid()) + ".log"
    logging.basicConfig(filename=logFileName, filemode='w',
                        format='%(asctime)s | %(levelname)s | %(message)s', 
                        datefmt='%d/%m/%Y %I:%M:%S %p', 
                        level=logging.INFO)
    logger.setLevel(logging.INFO)

    print("Log file = %s" % (logFileName))
    angrLogger = logging.getLogger('angr')
    angrLogger.setLevel('ERROR')
    #logging.getLogger('angr').setLevel('ERROR')
    
    # on met le niveau du logger à DEBUG, comme ça il écrit tout

    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
    '''
    file_handler = logging.FileHandler(logFileName)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    '''
    #Définition d'une liste de programmes qui contiendra les résultats de tous les mutants (classe Programme)
    programmes = []

    #tableau des adresses sur lesquelles seront faits les hooks
    adrhooks = []

    # déclaration du dictionnaire dans lequel on mettra les valeurs des registres pour tous les programmes déjà passés
    results = {}
    # déclaration du dictionnaire dans lequel on mettra les valeurs des registres pour le programme en cours de traitement
    resultsprov = {}
    # déclaration du dictionnaire trié dans lequel on mettra les valeurs des registres pour le programme en cours de traitement
    resultsprovtri = {}
    # déclaration du dictionnaire dans lequel on mettra les valeurs définitives des registres
    # pour le programme en cours de traitement : c'est celui qui sera fusionné avec results si le programme est de type "useful"
    resultsdef = {}

    #variable size pour le nombre de lignes du programme désassemblé
    size = 10000

    # certains hooks déclenchent des boucles à l'infini : on place un compteur maxi d'itérations pour en sortir
    # attention : ce paramètre est à ajuster selon le type de programme : il doit être calculé comme environ 2 fois le nombre
    # de steps du golden run (cette information est affichée par le programme à l'exécution)
    # si ce nombre est trop faible, la variable nbcrahsedsteps sera trop grande et s'il est trop élevé, le temps d'exécution sera
    # trop long
    maxsteps = 500   

    #variables pour compter le nombre de programmes par type : useful pour un mutant utile, useless pour un mutant inutile
    #crashedtime pour un mutant ayant généré un timeout d'exécution avec angr
    # et crashedsteps pour un mutant ayant généré une boucle infinie (ici > maxsteps)
    nbuseful=0
    nbuseless=0
    nbcrashedtime=0
    nbcrashedsteps=0
    #on va aussi compter le nombre de programmes pour lesquels angr a généré une erreur
    nberrorfound=0

    logging.info("---------------------------------------------------------")
    logging.info("Exécution de %s", __file__)
    logging.info("Programme binaire : %s", binaryFile)
    logging.info("Fonction analysée : %s", funcName)
    logging.info(" Limiter : %s", limiter)
    logging.info("---------------------------------------------------------")

    '''
    print("---------------------------------------------------------")
    print(" Programme binaire : ", binaryFile)
    print(" Fonction hookée : ", funcName)
    print(" Limiter : ", limiter)
    print("---------------------------------------------------------")
    print("")
    '''
    #on démarre : quelle heure est-il ? ceci sert à mesurer le temps d'exécution du programme
    start = time.time()

    #chargement du binaire et récupération d’un objet angr "proj" de type “Project”
    proj = angr.Project(binaryFile, load_options={'auto_load_libs':False})
    logging.info('Programme chargé')

    ##########################################################
    #on calcule les adresses sur lesquelles faire des hooks  #
    ##########################################################
    
    #on ne fera de hooks que sur les adresses de la fonction qu'on a passée en paramètres

    #on recherche la fonction sur laquelle on doit ajouter les hooks
    cfg=proj.analyses.CFGEmulated(keep_state=True)
    entry_func=cfg.kb.functions.function(name=funcName)

    #on ajoute le goldenrun au tableau des adresses de hooks pour pouvoir gérer son exécution dans le cadre général
    adrhooks.append(-1)

    #on balaie les blocs de la fonction
    nbHooks = 1
    logging.info("Calcul des adresses des instructions à remplacer par un hook...")
    for b in entry_func.blocks:
        # on désassemble chaque bloc du programme pour trouver ses instructions : chacune d'elle constituera l'adresse d'un hook
        for cs_insn in b.capstone.insns:
            nbHooks +=1
            adrhooks.append(cs_insn.address)
            logging.info(hex(cs_insn.address))

    logging.info("Nombre de programmes mutants à évaluer (hooks) : %d", nbHooks)

    '''
    print("---------------------------------------------------------")
    print(" Nombre de programmes mutants à évaluer (hooks) = %d" % (nbHooks))
    print("---------------------------------------------------------")
    print("")
    '''
    
    #ce code est à décommenter pour afficher les adresses où seront générées les hooks
    #print("Adresses des instructions à remplacer par un hook :")
    '''
    i=0
    while i < len(adrhooks):
        #print(hex(adrhooks[i]))
        logging.info(hex(adrhooks[i])
        i += 1
    '''
    # On initialise le compteur de mutants
    cptpgm = 0

    # on va boucler sur les programmes à générer, chacun correspondant à un mutant ou au golden run
    while cptpgm < len(adrhooks):

        #########################################################################################
        # pour chaque programme :                                                               #
        # 1- on active le hook qui fait le NOP (nothing) pour créer un programme mutant.        #
        # 2- on exécute le programme                                                            #
        # 3- on détermine le type du programme (useless ou useful)                              #
        #########################################################################################

        #####################################################################################
        # 1- on active le hook qui fait le NOP (nothing) pour créer un programme mutant.    #
        #####################################################################################

        # pas de hook pour le golden run
        if (adrhooks[cptpgm] != -1):

            if (cptpgm == (len(adrhooks)-1)):
	        # un hook sur une longueur de 4 par défaut pour la dernière instruction du programme
                length = 4
            else:
                # on calcule la longueur du remplacement
                length = adrhooks[cptpgm+1] - adrhooks[cptpgm]

	        # on effectue un remplacement sur la longueur calculée avant la prochaine instruction
            proj.hook(adrhooks[cptpgm], nothing, length)
            logging.debug("Hook installé sur le mutant %d à l'adresse %x", cptpgm, adrhooks[cptpgm] )

        ##############################
        # 2 on exécute le programme  #
        ##############################

        # on stocke l'id, l'adresse de hook du programme et un type par défaut dans un objet programme
        pgm = Programme(cptpgm, adrhooks[cptpgm], "useful", -1, "", 0)

        # On fait tourner le programme. On doit récupérer un objet SimulatorManager
        # réinitialisé pour pouvoir exécuter le programme de nouveau depuis le début.
        state=proj.factory.entry_state()
        # on positionne des options angr pour éviter l'explosion des noeuds lors du calcul
        # sans ces options, le programme ne fonctionne pas notamment s'il y a des boucles dans le binaire
        state.options.add(angr.options.LAZY_SOLVES)

        if limiter == "0" or limiter == "2":
            state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

        simgr=proj.factory.simulation_manager(state, save_unsat=True)

        if limiter == "1" or limiter == "2":
            simgr.use_technique(angr.exploration_techniques.LengthLimiter(20))

        # on vide les dictionnaires provisoires 
        resultsprov.clear()
        resultsprovtri.clear()
        resultsdef.clear()

        #on initialise le nombre de steps du programme à traiter pour les compter et arrêter la boucle si on dépasse max_steps
        nbsteps = 0

        # on boucle dans l'exécution du programme step par step tant que la stash active n'est pas vide
        # la stash active contient, dans angr, toutes les branches en cours d'exécution
        while (len(simgr.active) > 0):
            #on initialise une variable qui contient l'ensemble des branches actives du programmes
            j = 0
            '''
            #à décommenter pour printer des informations servant au debut
            if (len(simgr.active) > 0):
                #on imprime le bloc
                print(len(simgr.active))
                block = proj.factory.block(simgr.active[0].addr)
                print("nouveau bloc dans exec du programme", i, simgr.active[j].addr, " -step : ", nbsteps)
                print("len(simgr.active) : ", len(simgr.active), "len(simgr.errored : ", len(simgr.errored))
                #block.pp()
            '''
            '''
            if (len(simgr.active) > 0):
                #on imprime le bloc
                logging.debug(len(simgr.active))
                block = proj.factory.block(simgr.active[0].addr)
                logging.debug("nouveau bloc dans exec du programme", cptpgm, simgr.active[j].addr, " -step : ", nbsteps)
                logging.debug("len(simgr.active) : ", len(simgr.active), "len(simgr.errored : ", len(simgr.errored))
                #block.pp()
            '''
            #on balaie toutes occurences de la stash active pour ce step
            while (j < len(simgr.active)):

                #on stocke le state dans une variable
                s = simgr.active[j]

                # on stocke les clés de registre du golden run et
                # on stocke les clés de registres qui se situent après le hook pour les mutants
                if (cptpgm == 0 or s.addr > adrhooks[cptpgm]):
                    # ici, la valeur correspondra à l'instruction (registre r15)
                    #, ce qui nous permettra ensuite de retrouver les instructions en double et de les supprimer
                    # on ne stocke pas le registre 13 qui est le registre de pointeur de stack et qui perturbe la comparaison
                    # entre mutants
                    resultsprov[str(s.solver.eval(s.regs.r0)) + "-" + str(s.solver.eval(s.regs.r1)) + "-" +str(s.solver.eval(s.regs.r2)) + "-" + str(s.solver.eval(s.regs.r3)) + "-" + str(s.solver.eval(s.regs.r4)) + "-" + str(s.solver.eval(s.regs.r5)) + "-" + str(s.solver.eval(s.regs.r6)) + "-" + str(s.solver.eval(s.regs.r7)) + "-" + str(s.solver.eval(s.regs.r8)) + "-" + str(s.solver.eval(s.regs.r9)) + "-" + str(s.solver.eval(s.regs.r10)) + "-" + str(s.solver.eval(s.regs.r11)) + "-" + str(s.solver.eval(s.regs.r12)) + "-" + str(s.solver.eval(s.regs.r14)) + "-" + str(s.solver.eval(s.regs.r15)) + "-" + str(s.solver.eval(s.regs.cc_dep1)) ] = s.solver.eval(s.regs.r15)

                j += 1
            
            # à décommenter pour ajouter des informations de debug
            if (cptpgm == 0):
                logging.debug("avant step : adresse : ", hex(simgr.active[0].addr))
                #print("avant step : adresse : ", hex(simgr.active[0].addr))
            
            #on déclenche le step suivant en mesurant en combien de temps il s'exécute
            #en effet, un step trop long annonce une consommation mémoire excessive d'angr qui finit par ne plus répondre
            startstep = time.time()
            simgr = simgr.step()
            endstep = time.time()
            if (endstep-startstep) > 2 and cptpgm != 0:
                #un step trop long est mauvais signe pour la suite : on sort avec motif "timeout"
                pgm.typepgm = "crashed-time"
                break;

            #on incrémente le nombre de steps
            nbsteps +=1

            #on sort si on a atteint la limite du nombre de steps qu'on s'est fixé
            #en effet, il arrive que les hooks déclenchent des boucles infinies auquel cas, il vaut mieux arrêter l'exécution
            if (nbsteps > maxsteps) and cptpgm != 0:
                pgm.typepgm = "crashed-steps"
                break;

        #on affiche le nombre de steps du golden run : il est intéressant car il permet de positionner judicieusement
        #la variable maxsteps : on met à peu près le double de la valeur affichée
        if cptpgm == 0:
            logging.info(" Nombre de steps dans le programme Golden Run : %d", nbsteps)
            '''
            print("---------------------------------------------------------")
            print(" Nombre de steps dans le programme Golden Run : ", nbsteps)
            print("---------------------------------------------------------")
            '''
        
        # on a fini les steps de ce programme : il faut quand même stocker les infos de la dernière instruction
        # nous avons un problème sur la dernière instruction : les registres r14 et r15 ne sont pas fiables pour la comparaison
        # nous les avons donc éliminés

        # la branche du programme est classée dans la stash "unconstrained"
        # quand l'exécution a généré plus de 256 branches possibles 
        if len(simgr.unconstrained) > 0:
            j=0
            while (j < len(simgr.unconstrained)):

                #on stocke le state dans une variable
                s = simgr.unconstrained[j]
            
                #print("stashunconstrained : ",j," dans le programme ",cptpgm," à l'adresse ",s)
                # on met la clé dans le dictionnaire
                resultsprov[str(s.solver.eval(s.regs.r0)) + "-" + str(s.solver.eval(s.regs.r1)) + "-" + str(s.solver.eval(s.regs.r2)) + "-" + str(s.solver.eval(s.regs.r3)) + "-" + str(s.solver.eval(s.regs.r4)) + "-" + str(s.solver.eval(s.regs.r5)) + "-" + str(s.solver.eval(s.regs.r6)) + "-" + str(s.solver.eval(s.regs.r7)) + "-" + str(s.solver.eval(s.regs.r8)) + "-" + str(s.solver.eval(s.regs.r9)) + "-" + str(s.solver.eval(s.regs.r10)) + "-" + str(s.solver.eval(s.regs.r11)) + "-" + str(s.solver.eval(s.regs.r12)) + "-" + str(s.solver.eval(s.regs.cc_dep1))] = 99999998
 
                j += 1

        # la branche du programme est classée dans la stash "deadended"
        # quand elle a terminé son exécution de manière naturelle
        if len(simgr.deadended) > 0:
            j=0
            while (j < len(simgr.deadended)):

                #on stocke le state dans une variable
                s = simgr.deadended[j]
            
                #print("stashdeadended : ",j," dans le programme ",cptpgm," à l'adresse ",s)
                # on met la clé dans le dictionnaire
                resultsprov[str(s.solver.eval(s.regs.r0)) + "-" + str(s.solver.eval(s.regs.r1)) + "-" +str(s.solver.eval(s.regs.r2)) + "-" + str(s.solver.eval(s.regs.r3)) + "-" + str(s.solver.eval(s.regs.r4)) + "-" + str(s.solver.eval(s.regs.r5)) + "-" + str(s.solver.eval(s.regs.r6)) + "-" + str(s.solver.eval(s.regs.r7)) + "-" + str(s.solver.eval(s.regs.r8)) + "-" + str(s.solver.eval(s.regs.r9)) + "-" + str(s.solver.eval(s.regs.r10)) + "-" + str(s.solver.eval(s.regs.r11)) + "-" + str(s.solver.eval(s.regs.r12)) + "-" + str(s.solver.eval(s.regs.cc_dep1)) ] = 99999999

                j += 1

        # la branche du programme est classée dans la stash "errored"
        # quand angr a généré des erreurs
        # dans ce cas, la lecture des registres n'est pas possible : on met juste l'information sur le programme
        if len(simgr.errored) > 0:
            pgm.errorfound = 1

        #############################################################
        # 3- on détermine le type du programme (useless ou useful)  #
        #############################################################
        
        # on a terminé le traitement du programme :
        # il faut maintenant déterminer si le programme est useful ou crashé
        # pour cela, on va trier resultsprov et pour chaque instruction, enlever les adresses en double générées par les boucles
 
        # on trie resultsprov par valeur (le pointeur d'instruction) 
        # et on met le résultat dans un autre dictionnaire : resultsprovtri
        #resultsprovtri = OrderedDict(sorted(resultsprov.items(), key=lambda t:t[1], reverse = True))
 
        # on va lire séquentiellement le dictionnaire trié et seulement si une instruction n'est pas en double
        # on l'insère dans un nouveau dictionnaire : resultsdef
        cle_ante = -1
        val_ante = -1
        count_val_ante = 0
        for cle, valeur in sorted(resultsprov.items(), key=lambda x: x[1]):
            #print("clé et valeur triés",cle, valeur, "clé et valeur ante", cle_ante, val_ante)
            #si la valeur a changé depuis la lecture précédente
            if (valeur != val_ante):
                # on regarde combien de lignes on avait de l'ancienne valeur et s'il n'y en a qu'une, on insère dans resultsdef
                # avec comme valeur, l'id du programme
                if count_val_ante == 1:
                    #print("on garde : ",cle_ante)
                    resultsdef[cle_ante] = cptpgm
                #on remet le compteur à 1
                count_val_ante = 1
                #on stocke la nouvelle valeur lue dans val_ante
                val_ante = valeur
                #on stocke la nouvelle clé lue dans cle_ante
                cle_ante = cle
            else:
                #on arrive ici si on a lu une ligne qui a le même pointeur d'instruction que la précédente
                #dans ce cas, on incrémente le compteur qui indique combien de lignes sont lues avec ce pointeur d'instructions
                count_val_ante += 1
        #il faut aussi insérer la dernière ligne après la boucle
        if count_val_ante == 1:
             #print("on garde à la fin : ",cle_ante)
             resultsdef[cle_ante] = cptpgm

        # lignes à décommenter pour afficher des informations de debug
        '''
        print("programme", cptpgm)
        print("   adrhooks[cptpgm]", adrhooks[cptpgm])
        print("   contenu de results")
        for cle, valeur in results.items():
            print (cle, valeur)
        #print("   contenu de resultsprov")
        #for cle, valeur in resultsprov.items():
        #    print (cle, valeur)
        print("   contenu de resultsdef")
        for cle, valeur in resultsdef.items():
            print (cle, valeur)
        print(" ")
        '''
        logging.debug("programme", cptpgm)
        logging.debug("   adrhooks[cptpgm]", adrhooks[cptpgm])
        logging.debug("   contenu de results")
        for cle, valeur in results.items():
            logging.debug (cle, valeur)
        #print("   contenu de resultsprov")
        #for cle, valeur in resultsprov.items():
        #    print (cle, valeur)
        logging.debug("   contenu de resultsdef")
        for cle, valeur in resultsdef.items():
            logging.debug (cle, valeur)

        # maintenant qu'on n'a que des informations exploitables dans le dictionnaire resultsdef (on a enlevé les lignes
        # correspondant à des boucles), et pour tous les programmes qui n'ont pas crashé
        # on va chercher si l'une des lignes restantes a déjà été stockée dans results
        # si on la trouve dans results, le programme sera useless et sinon, il sera useful
        if (pgm.typepgm != "crashed-time" and pgm.typepgm != "crashed-steps"):
            for cle, valeur in resultsdef.items():
                if (cle in results):
                    #print("    clé et valeurs trouvées", cle, valeur)
                    pgm.regcmp = cle
                    pgm.typepgm = "useless"
                    pgm.idpgmuseful = results.get(cle)
                    break

        #print("programme ", cptpgm, " : ", pgm.typepgm)
        logging.debug("programme ", cptpgm, " : ", pgm.typepgm)

        # on stocke le programme traité dans la table des programmes
        programmes.append(pgm)

        # si le programme est useful, on fusionne le dictionnaire provisoire avec le dictionnaire général
        # on comptabilise également le programme traité dans une des catégories pour l'impression de statistiques
        if (pgm.typepgm == "useful"):
            results.update(resultsdef)
            nbuseful +=1
        elif pgm.typepgm == "crashed-time":
            nbcrashedtime +=1
        elif pgm.typepgm == "crashed-steps":
            nbcrashedsteps +=1
        else:
            nbuseless +=1

        # est-ce qu'angr a généré une erreur pour ce programme ?
        if pgm.errorfound == 1:
            nberrorfound +=1

        # si on n'est pas en train de traiter le golden run, on enlève le hook du programme pour le tour suivant
        if adrhooks[cptpgm] >= 0:
            proj.unhook(adrhooks[cptpgm])

        #on passe au programme suivant
        cptpgm=cptpgm+1


    ##########################################################
    # impression des résultats                               #
    ##########################################################
    
    i = 0
    '''
    print("---------------------------------------------------------")
    print(" Résultats détaillés")
    print("---------------------------------------------------------")
    '''
    logging.info("---------------------------------------------------------")
    logging.info(" Résultats détaillés")
    logging.info("---------------------------------------------------------")
    while i < len(programmes):
        if (programmes[i].adrhook == -1):
            #print("Le programme ", programmes[i].idpgm, "est le golden run")
            logging.info("Le programme %d est le golden run.", programmes[i].idpgm)
        else:
            if (programmes[i].typepgm == "useful"):
                #print("Le programme ", programmes[i].idpgm, " dont le hook est à l'adresse ", hex(programmes[i].adrhook), " est ", programmes[i].typepgm)
                logging.info("Le programme %d / %s est %s", programmes[i].idpgm, hex(programmes[i].adrhook), programmes[i].typepgm)
            elif (programmes[i].typepgm == "crashed-time"):
                #print("Le programme ", programmes[i].idpgm, " dont le hook est à l'adresse ", hex(programmes[i].adrhook), " a crashé à cause du timeout ")
                logging.info("Le programme %d / %x a crashé à cause du timeout.", programmes[i].idpgm, hex(programmes[i].adrhook) )
            elif (programmes[i].typepgm == "crashed-steps"):
                #print("Le programme ", programmes[i].idpgm, " dont le hook est à l'adresse ", hex(programmes[i].adrhook), " a crashé à cause d'une boucle infinie ")
                logging.info("Le programme %d / %x a crashé à cause d'une boucle infinie ", programmes[i].idpgm, hex(programmes[i].adrhook))
            else:
                #print("Le programme ", programmes[i].idpgm, " dont le hook est à l'adresse ", hex(programmes[i].adrhook), " est ", programmes[i].typepgm, " : il donne le même résultat que le programme ", programmes[i].idpgmuseful, " pour les valeurs de registres : ", programmes[i].regcmp)
                logging.info("Le programme %d / %s est %s, idem que programme %d. Registres R0-R13 = %s.", 
                                programmes[i].idpgm, hex(programmes[i].adrhook),
                                programmes[i].typepgm, programmes[i].idpgmuseful, programmes[i].regcmp)
        if (programmes[i].errorfound == 1):
            #print("   Ce programme a généré des erreurs dans angr : son résultat doit être réexaminé")
            logging.info("   Ce programme a généré des erreurs dans angr : son résultat doit être réexaminé.")
        i += 1
    
    i = 0
    #print("---------------------------------------------------------")
    #print(" Résultats détaillés des programmes useful")
    #print("---------------------------------------------------------")

    logging.info("---------------------------------------------------------")
    logging.info(" Résultats détaillés des programmes useful")
    logging.info("---------------------------------------------------------")
    
    #print("Les programmes useful ont des hooks aux adresses suivantes :")
    logging.info("Les programmes useful ont des hooks aux adresses suivantes :")
    while i < len(programmes):
        
        if (programmes[i].typepgm == "useful"):
            if (programmes[i].errorfound == 1):
                #print("   ", hex(programmes[i].adrhook), " avec erreurs !")
                logging.info("   %s avec erreurs !", hex(programmes[i].adrhook))
            else:
                #print("   ", hex(programmes[i].adrhook))
                logging.info("   %s", hex(programmes[i].adrhook))
        i += 1
    

    # L'analyse du programme est terminée. quelle heure est-il ? On affiche la durée du traitement
    end = time.time()
    '''
    print("")
    print("---------------------------------------------------------")
    print(" Résultats synthétiques")
    print("---------------------------------------------------------")
    print("Durée du traitement : ", round(end-start,2), " secondes")
    print("Nombre de programmes useful : ", nbuseful)
    print("Nombre de programmes crashés par timeout : ", nbcrashedtime)
    print("Nombre de programmes crashés par boucle infinie : ", nbcrashedsteps)
    print("Nombre de programmes useless : ", nbuseless)
    print("Nombre de programmes pour lesquels Angr a généré des erreurs : ", nberrorfound)
    print("Taux de nettoyage (useless+crashed)/total : ", round((nbuseless+nbcrashedtime+nbcrashedsteps)*100/(nbuseful + nbuseless + nbcrashedtime + nbcrashedsteps),2), "%")
    '''
    logging.info("---------------------------------------------------------")
    logging.info(" Résultats synthétiques")
    logging.info("---------------------------------------------------------")
    logging.info("Durée du traitement : %f sec.", round(end-start,2) )
    logging.info("Nombre de programmes useful : %d", nbuseful)
    logging.info("Nombre de programmes crashés par timeout : %d", nbcrashedtime)
    logging.info("Nombre de programmes crashés par boucle infinie : %d", nbcrashedsteps)
    logging.info("Nombre de programmes useless : %d", nbuseless)
    logging.info("Nombre de programmes pour lesquels angr a généré des erreurs : %d", nberrorfound)
    logging.info("Taux de nettoyage (useless+crashed)/total : %f", round((nbuseless+nbcrashedtime+nbcrashedsteps)*100/(nbuseful + nbuseless + nbcrashedtime + nbcrashedsteps),2))

    # remember to close the handlers
    for handler in logger.handlers:
        handler.close()
        logger.removeFilter(handler)

if __name__ == "__main__":
    main(sys.argv[1:])



