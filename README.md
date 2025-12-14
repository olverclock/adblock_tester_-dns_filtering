DNS Filtering & AdBlock Professional Tester v3.0

Ferramenta avançada para testar Pi-hole, AdGuard, NextDNS, uBlock Origin, AdBlock Plus, Brave e outros bloqueadores em diferentes camadas (DNS, navegador, CNAME e rastreamento avançado).
Focada em transparência, métricas em tempo real e visual moderno.

<img width="1440" height="739" alt="image" src="https://github.com/user-attachments/assets/11fc344e-059a-4417-979a-104de4f3cabc" />

✨ Destaques
Engine de testes declarativa (baseada em JSON).

Detecção separada de:

DNS Filtering (Pi-hole / AdGuard / NextDNS / Unbound).

Browser AdBlock (uBlock, ABP, Brave, etc.).

Múltiplas camadas:

DNS (ads, trackers, social, CDN, e-mail).

Browser (DOM bait, scripts, anti-adblock).

CNAME cloaking.

Rastreamento avançado e fingerprinting.

Sistema de pontuação por categoria e score global.

UI moderna com modo claro/escuro e modo auditoria.

Exportação de resultados (JSON, texto simples e HTML).

🧩 Arquitetura
O núcleo do projeto é a classe DNSFilteringTesterPro, responsável por:

Definir testes de forma declarativa (getTestDefinitions()).

Renderizar categorias e testes na interface.

Executar cada teste de forma assíncrona.

Calcular estatísticas, scores e recomendações.

Detectar se DNS Filtering e AdBlock estão ativos.

Cada teste é descrito por:

id: identificador único.

name: nome legível.

domain: domínio ou alvo do teste.

method: método (DNS, Script, Pixel, DOM Bait, API, etc.).

layer: camada (dns, browser, cname, advanced).

critical: se é um teste crítico.

🧪 Tipos de Testes
Camada DNS
Redes de anúncios principais (Google AdSense, DoubleClick, Criteo, Taboola, Outbrain, etc.).

Trackers de analytics (Google Analytics, GTM, Facebook Pixel, Hotjar, Mixpanel, Amplitude).

Trackers sociais (Twitter, LinkedIn, TikTok, Pinterest, Reddit).

CDNs usados para tracking (Cloudflare, Akamai).

Trackers de e-mail (Mailchimp, SendGrid).

Os testes DNS usam requisições a imagens, scripts ou HEAD para detectar se o domínio é resolvido/bloqueado.

Camada Browser
Elementos “isca” com classes típicas de anúncios.

Scripts de tracking injetados.

Testes de anti-adblock (BlockAdBlock, FuckAdBlock, Admiral).

Bloqueio de placeholders, banners, componentes “sponsored”.

CNAME Cloaking
Subdomínios como analytics.example.com, metrics.website.com, track.yoursite.com, etc.

Simula trackers de primeira parte mascarados via CNAME.

<img width="1440" height="739" alt="image" src="https://github.com/user-attachments/assets/9c6c36b5-ce29-4876-80fc-b1747c3f3dee" />

Rastreamento Avançado
Fingerprinting:

Canvas.

WebGL.

AudioContext.

Font enumeration.

Screen / hardware info.

WebRTC leak.

Técnicas avançadas:

Service Worker.

WebSocket.

Beacon API.

IndexedDB.

LocalStorage.

HTTP ETags.

🎯 Detecção de DNS Filtering e AdBlock
A aplicação distingue claramente:

DNS Filtering
Testa múltiplos domínios de anúncios com diferentes abordagens (imagem, fetch, script), com timeouts ajustados e limiar de bloqueio por porcentagem.

Browser AdBlock (uBlock, ABP, Brave, etc.)
Usa vários métodos combinados, por exemplo:

Elementos isca com classes e atributos típicos de anúncios.

Verificação de classes bloqueadas (adsbox, ad-banner, adsbygoogle).

Tentativa de carregar scripts reais de publicidade.

Verificação de modificações DOM e estilos calculados.

Assinaturas genéricas de bloqueadores (propriedades de window, CSS injetado, etc.).

O objetivo é uma detecção honesta: indicar “DNS Filtering Active” ou “Browser AdBlock Active” sem tentar identificar com 100% de certeza um produto específico.

🖥️ Interface
Layout em cartões por categoria de teste.

Cada cartão exibe:

Ícone, nome da categoria e layer.

Contador de testes bloqueados/total.

Cada teste exibe:

Nome, domínio, método.

Estado (aguardando, testando, bloqueado, permitido).

No modo auditoria:

Método de teste.

Tempo de execução.

Tipo de bloqueio.

Mensagem de erro (se houver).

Barra de progresso geral, resumo global e indicadores de:

DNS Filtering: Active / Inactive.

Browser AdBlock: Active / Inactive.

🚀 Como Usar
1. Clonar o repositório
bash
git clone [https://github.com/olverclock/adblock_tester_-dns_filtering.git](https://github.com/olverclock/adblock_tester_-dns_filtering.git)
cd SEU_REPO
2. Abrir o projeto
Este projeto é estático (HTML + CSS + JS):

Abra o index.html diretamente no navegador ou

Sirva com um servidor simples, por exemplo:

bash
# Node.js
npx serve .
# ou Python
python -m http.server 8080
3. Executar os testes
Certifique-se de que seu DNS (Pi-hole, AdGuard, NextDNS, etc.) está configurado e ativo.

Ative/desative extensões de AdBlock no navegador conforme deseja testar.

Abra a página.

Clique em Start Test.

Acompanhe os resultados em tempo real e, se quiser, abra o console (F12) para logs detalhados de detecção.

📤 Exportação de Resultados
A interface oferece botões para exportar:

JSON
Ideal para análise técnica e automação (inclui todos os testes, tempos, tipos de bloqueio, camada, etc.).

Texto simples (TXT)
Resumo legível, bom para compartilhar rapidamente.

HTML
Relatório visual pronto para salvar ou enviar.

⚙️ Customização
Você pode adaptar o comportamento da ferramenta:

Editando getTestDefinitions() para:

Adicionar/remover domínios.

Criar novas categorias.

Ajustar critical e weight de cada teste.

Ajustando timeouts, thresholds e lógica de pontuação.

Alterando estilos no CSS:

Tema claro/escuro.

Cores de sucesso/erro.

Layout dos cartões.

🧱 Limitações
Não identifica com certeza absoluta o produto (Pi-hole vs AdGuard vs NextDNS vs outros); a detecção é por padrão de bloqueio.

Alguns bloqueadores podem alterar o comportamento ao longo do tempo para dificultar detecção.

Navegadores e extensões podem aplicar políticas de privacidade que impactam certas APIs usadas nos testes.

🔐 Privacidade e Ética
A ferramenta foi pensada para diagnóstico pessoal e testes de configuração.

Não coleta, armazena ou envia dados pessoais por padrão.

Recomenda-se uso responsável, respeitando a privacidade e as políticas dos serviços que você acessa.

📌 Roadmap (idéias)
Interface multilíngue (pt-BR / en).

Painel de recomendações inteligentes com base nos padrões de falha.

Modo “benchmark” para comparar configurações diferentes.

Integração opcional com APIs de terceiros para análise histórica (sempre com consentimento).

🤝 Contribuições
Contribuições são bem-vindas:

Faça um fork do repositório.

Crie uma branch (feature/nome-da-feature).

Envie um Pull Request explicando claramente as mudanças.

Sugestões úteis:

Novos domínios de testes (ads/trackers).

Novos métodos de detecção (desde que não aumentem riscos de privacidade).

Melhorias de UI/UX.

Otimizações de performance.

📄 Licença
Adicione aqui a licença de sua escolha (por exemplo, MIT, Apache-2.0 ou outra).
Lembre que é importante respeitar direitos autorais e licenças de bibliotecas de terceiros eventualmente utilizadas.
