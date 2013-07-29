# Nom de commande originel. Ne surtout pas changer cette variable
cmd_original_name=cranspasswords

# Nom de la commande, par défaut cranspasswords
# Vous pouvez la modifier
cmd_name=cranspasswords

# Expression régulière et son remplacement, pour le renommage
before=cmd_name = '${cmd_original_name}'
after=cmd_name = '${cmd_name}'
before2=cmd_name=${cmd_original_name}
after2=cmd_name=${cmd_name}

# Path du sudoer-file utilisé pour autoriser l'accès au script serveur
sudoer_file_path=/etc/sudoers.d/${cmd_name}
# Groupe qui aura le droit de lire les fichiers de mot de passe
# (indépendamment de pouvoir les déchiffrer)
sudoer_group=respbats

build:
	@echo "Pour installer ${cmd_name} :"
	@echo "Exécutez make install pour installer le client pour vous."
	@echo "Exécutez sudo make install-server pour installer le serveur sur la machine."

rename:
	@echo "Modification des variables pour renommer '${cmd_original_name}' en '${cmd_name}'"
	@sed -i "s/^${before}$$/${after}/" serverconfig.example.py clientconfig.example.py
	@sed -i "s/^${before2}$$/${after2}/" server

rerename:
	@echo "Remise en place des variables passées à '${cmd_name}' en leur valeur de départ '${cmd_original_name}'"
	@sed -i "s/^${after}$$/${before}/" serverconfig.example.py clientconfig.example.py
	@sed -i "s/^${after2}$$/${before2}/" server

install:
	@if [ "${cmd_name}" != "${cmd_original_name}" ]; then make --quiet rename; fi
	install -d -m 0755 ~/bin
	install -m 0755 client.py ~/bin/${cmd_name}
	install -d -m 0755 ~/.config/${cmd_name}
	install -m 0644 clientconfig.example.py ~/.config/${cmd_name}
	@if [ "${cmd_name}" != "${cmd_original_name}" ]; then make --quiet rerename; fi

install-server:
	@echo "Création du sudoer-file."
	@echo "# Autorisation locale d'éxécution de ${cmd_name}" > ${sudoer_file_path}
	@echo " %${sudoer_group}   ALL=(root) NOPASSWD: /usr/local/bin/${cmd_name}-server" >> ${sudoer_file_path}
	install -g root -o root -m 0755 server.py /usr/local/bin/${cmd_name}-server
	install -d -g root -o root -m 0755 /etc/${cmd_name}/
	install -g root -o root -m 0644 serverconfig.example.py /etc/${cmd_name}/serverconfig.py
	install -d -m 700 /var/lib/${cmd_name}/db/
