# 1. Base para compilación: Ubuntu LTS
FROM ubuntu:22.04

# Variable para la versión de Squid que queremos
ENV SQUID_VERSION=6.9

# 2. Instalar dependencias
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        openssl \
        ca-certificates \
        pkg-config \
        libxml2-dev \
        libnetfilter-conntrack-dev \
        libpam0g-dev \
        libcppunit-dev \
        libtool \
        curl \
        gnupg \
        adduser \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 3. El usuario 'proxy' ya existe en esta imagen base

# 4. Descargar y descomprimir el código fuente
RUN curl -o squid.tar.gz http://www.squid-cache.org/Versions/v6/squid-${SQUID_VERSION}.tar.gz
RUN tar -zxvf squid.tar.gz && rm squid.tar.gz

# 5. Compilar Squid con las banderas de SSL habilitadas
RUN cd squid-${SQUID_VERSION} && \
    ./configure \
        --prefix=/usr \
        --localstatedir=/var/spool/squid \
        --libexecdir=/usr/lib/squid \
        --datadir=/usr/share/squid \
        --sysconfdir=/etc/squid \
        --with-logdir=/var/log/squid \
        --with-openssl \
        --enable-ssl-crtd \
        --enable-eui \
    && \
    make -j$(nproc) \
    && \
    make install

# 6. Limpiar el código fuente
RUN cd .. && rm -rf squid-${SQUID_VERSION}

# --- APLICACIÓN DE CONFIGURACIÓN Y PERMISOS ---

# 7. Copiar nuestro squid.conf
COPY squid.conf /etc/squid/squid.conf

# 8. Crear directorios
RUN mkdir -p /etc/squid/ssl
RUN mkdir -p /var/log/squid
# (No creamos ssl_db, dejamos que la herramienta lo haga)

# 9. Generar el certificado CA
RUN openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=XX/ST=None/L=None/O=Squid/CN=squid.lab.local" \
    -keyout /etc/squid/ssl/ca.key -out /etc/squid/ssl/ca.crt

# 10. Asignar permisos AL USUARIO 'proxy'
RUN chown -R proxy:proxy /var/spool/squid
RUN chown -R proxy:proxy /var/log/squid
RUN chown -R proxy:proxy /etc/squid/ssl
RUN chown proxy:proxy /etc/squid/squid.conf

# 11. Inicializar la base de datos de SSL
RUN su proxy -s /bin/sh -c "/usr/lib/squid/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB"

# 12. Comando de inicio
CMD ["/usr/sbin/squid", "-N", "-YC", "-f", "/etc/squid/squid.conf"]
