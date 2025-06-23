#!/usr/bin/env bash
# ================================
# 🔐 VALIDADOR DE SEGURIDAD URDIMBRE
# ================================

set -eo pipefail

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ========================================================
# 1. CARGAR VARIABLES DE ENTORNO DESDE .env
# ========================================================
if [[ -f .env ]]; then
  # exporta todas las vars definidas en .env (ignorando comentarios)
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
  echo -e "${GREEN}✅ Variables de entorno cargadas desde .env${NC}"
else
  echo -e "${YELLOW}⚠️  No se encontró archivo .env; usando valores por defecto del script${NC}"
fi

echo
echo "🔍 Iniciando validación de seguridad..."
echo

# ========================================================
# 2. VALIDAR .env
# ========================================================
echo "ℹ️  1. VALIDANDO ARCHIVO .env"
if [[ -f .env ]]; then
  echo -e "${GREEN}✅ Archivo .env encontrado${NC}"
else
  echo -e "${RED}❌ .env no encontrado${NC}"
fi

# ... aquí el resto de chequeos sobre .env (longitud de JWT, hex, DB_PASSWORD, etc.)

# ========================================================
# 3. VALIDAR CÓDIGO JAVA
# ========================================================
echo
echo "ℹ️  2. VALIDANDO CÓDIGO JAVA"
# Busca literales sospechosas de secrets
SECRETS_COUNT=$(grep -R --include="*.java" -nE "(password|secret|token)\s*=\s*\"[^\"]+\"" src/ | wc -l)
if (( SECRETS_COUNT > 0 )); then
  echo -e "${RED}❌   ${SECRETS_COUNT} posibles secrets hardcodeados encontrados${NC}"
else
  echo -e "${GREEN}✅ No se detectaron secrets hardcodeados en Java${NC}"
fi

# ========================================================
# 4. VALIDAR application.properties
# ========================================================
echo
echo "ℹ️  3. VALIDANDO application.properties"
# Comprobar uso de variables de entorno
grep -E '=\$\{[A-Za-z_][A-Za-z0-9_]*(:[^}]*)?\}' application.properties \
  && echo -e "${GREEN}✅ application.properties usa variables de entorno${NC}" \
  || echo -e "${RED}❌ No se detecta uso de variables de entorno${NC}"

# ========================================================
# 5. VALIDAR .gitignore
# ========================================================
echo
echo "ℹ️  4. VALIDANDO .gitignore"
for pattern in ".env" "*.env" "application-secret.properties" "*.key" "*.pem"; do
  if grep -xFq "$pattern" .gitignore; then
    echo -e "${GREEN}✅ Patrón '$pattern' protegido en .gitignore${NC}"
  else
    echo -e "${YELLOW}⚠️  Patrón '$pattern' NO está en .gitignore${NC}"
  fi
done

# ========================================================
# 6. PERMISOS DE ARCHIVOS
# ========================================================
echo
echo "ℹ️  5. VERIFICANDO PERMISOS DE ARCHIVOS"
if [[ -f .env ]]; then
  perms=$(stat -c "%a" .env)
  if (( perms <= 644 )); then
    echo -e "${GREEN}✅ Permisos de .env son seguros (${perms})${NC}"
  else
    echo -e "${RED}❌ Permisos de .env demasiado abiertos (${perms}); usa chmod 644 .env${NC}"
  fi
fi

# ========================================================
# 7. GENERACIÓN DE JWT SECRET (opcional)
# ========================================================
echo
echo "ℹ️  6. GENERADOR DE JWT SECRET SEGURO"
read -r -p "¿Generar nuevo JWT_SECRET_KEY? [y/N]: " gen
if [[ "$gen" =~ ^[Yy]$ ]]; then
  newkey=$(openssl rand -hex 64)
  echo -e "${GREEN}✅ Nuevo JWT_SECRET_KEY (hexadecimal):${NC}"
  echo "$newkey"
  echo
  echo "📋 Copia este valor a tu .env bajo JWT_SECRET_KEY"
fi

echo
echo "🔐 Validación completada"
