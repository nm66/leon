# leon
programme python de nettoyage de mutants d'un code binaire basé sur Angr

-b nom_du_fichier_binaire
-f nom_de_la_fonction
-l options_optimisation_angr (0, 1 ou 2)

Leon crée des mutants en remplaçant successivement chaque instruction de la fonction du code binaire par un NOP créant ainsi autant de mutants qu'il y a d'instructions dans la fonction.
Leon catégorise ensuite les mutants en ne classant "useful" que les mutants produisant un résultat différent d'un autre ou du golden run.
