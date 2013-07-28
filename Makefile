# Nom de commande originel. Ne surtout pas changer cette variable
cmd_original_name=cranspasswords

# Nom de la commande, par défaut cranspasswords
# Vous pouvez la modifier
cmd_name=bdepasswords

# Expression régulière et son remplacement, pour le renommage
before=cmd_name = '${cmd_original_name}'
after=cmd_name = '${cmd_name}'
before2=cmd_name=${cmd_original_name}
after2=cmd_name=${cmd_name}

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
	install -d ~/bin
	install client.py ~/bin/${cmd_name}
	install -d ~/.config/${cmd_name}
	install clientconfig.py ~/.config/${cmd_name}
	@if [ "${cmd_name}" != "${cmd_original_name}" ]; then make --quiet rerename; fi

install-server:
