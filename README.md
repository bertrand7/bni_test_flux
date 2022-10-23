# test_flux

install :
---------

make

ou :

gcc -o test_flux test_flux.c

ou :

gcc -w -Wall -O3 -o test_flux test_flux.c

pour l'usage :
----------------
<pre>
./test_flux -h

Usage : flux_test [options]                                              
                                                                         
 Teste les connexions définies dans le fichier : 'connextions.ip'
 ou celui indiqué par l'otption (-i ou --input-path)                     
 et écrit le résultat dans le fichier 'connextions_result.dat'
 ou celui indiqué par l'options (-o ou --output-path)                    
 Le timeout par défaut est de 2000 millisecondes
---------                                                                
Options :                                                                
                                                                         
 -h --help            affiche l'aide.                                    
                                                                         
 -t --timeout         Timeout en millisecondes.                          
                                                                         
 -i --input-path      Fichier d'ip avec le format suitant                
                                                                         
                      Chemin par défaut : 'connextions.ip'
                      Format :                                           
                       &lt;ip&gt; &lt;no-port&gt; &lt;description&gt;
                      Exemple:                                           
                      192.168.1.1 2783 livbox                            
                                                                         
 -o --output-path     Fichier dans lequel sont stoqués les résultats.    
                      Chemin par défaut : 'connextions_result.dat'
                      Format :                                           
                      &lt;entry-file-first-col&gt;:&lt;ipv4&gt;:&lt;found-fqdn&gt;:&lt;port&gt;:&lt;description&gt;:&lt;ok|ko|to&gt;
                      ok : la connexion répond correctement.             
                      ko : la connexion répond avec une erreur.          
                      to : la connexion ne réponds pas dans le temps     
                           défini par le timeout.            
</pre>

