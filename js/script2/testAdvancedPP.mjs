// js/script2/testAdvancedPP.mjs
import { logS2, PAUSE_S2 } from './s2_utils.mjs';

export async function testAdvancedPPS2() {
    const FNAME = 'testAdvancedPPS2';
    logS2("--- Teste: PP Avançado (Gadgets++) ---", 'test', FNAME);

    const propsToPollute = [
        // Object.prototype
        { name: 'constructor', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => (obj.constructor === pollutedValue && typeof pollutedValue !== 'function') ? 'Object.constructor foi poluído para um valor não funcional!' : null },
        { name: '__proto__', proto: Object.prototype, protoName: 'Object',
          // Poluir __proto__ diretamente no Object.prototype é extremamente perigoso e geralmente não é o vetor.
          // O teste aqui verificaria se a propriedade __proto__ em uma instância é o valor poluído.
          gadgetCheck: (obj, pollutedValue) => {
            try {
                // Tentar mudar o protótipo via __proto__ e verificar se reflete
                // Esta parte é mais para ver se a propriedade __proto__ em si foi poluída.
                if (obj.__proto__ === pollutedValue) return `Object.prototype.__proto__ foi poluído (valor da propriedade __proto__ em instâncias)!`;
            } catch (e) { /* pode falhar */ }
            return null;
          }},
        { name: 'isAdminPPTest', proto: Object.prototype, protoName: 'Object', // Propriedade nova, mais segura
          gadgetCheck: (obj, pollutedValue) => obj.isAdminPPTest === pollutedValue ? 'Nova propriedade Object.prototype.isAdminPPTest poluída com sucesso!' : null },
        { name: 'valueOf', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.valueOf === pollutedValue) { // Verifica se a própria função foi substituída
                 try { obj.valueOf(); return "Object.valueOf sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Object.valueOf sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},
        { name: 'toString', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.toString === pollutedValue) {
                 try { obj.toString(); return "Object.toString sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Object.toString sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},
        { name: 'hasOwnProperty', proto: Object.prototype, protoName: 'Object',
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.hasOwnProperty === pollutedValue) {
                 try { obj.hasOwnProperty('test'); return "Object.hasOwnProperty sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Object.hasOwnProperty sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},

        // Element & Node prototypes - Foco em verificar se a *instância* herda
        // Evitar ler/escrever diretamente em Element.prototype.innerHTML, etc.
        { name: 'data-pp-test', proto: Element.prototype, protoName: 'Element', createTarget: () => document.createElement('div'),
          gadgetCheck: (obj, pollutedValue) => obj.getAttribute('data-pp-test') === pollutedValue ? 'Atributo data-pp-test via Element.prototype poluído!' : null,
          // Para testar setters como innerHTML, a poluição deve ser no setter, o que é mais complexo.
          // Aqui, testamos uma propriedade/atributo que pode ser herdado de forma mais simples.
          // Ou, para testar se o *acesso* a innerHTML é afetado:
          polluteLogic: (targetProto, propName, pValue) => { Object.defineProperty(targetProto, propName, { value: pValue, writable: true, configurable: true }); },
          checkLogic: (instance, propName, pValue) => instance[propName] === pValue
        },
        { name: 'innerHTML', proto: Element.prototype, protoName: 'Element', createTarget: () => document.createElement('div'),
          // Tentativa de poluir innerHTML em uma instância para ver se o protótipo pode influenciar setters/getters
          // Isso é complexo. O teste mais simples é ver se uma *nova* propriedade é herdada.
          // Se o objetivo é interceptar o setter/getter de innerHTML, isso requer Object.defineProperty no protótipo.
          gadgetCheck: (obj, pollutedValue) => {
            // É difícil verificar a poluição de innerHTML no protótipo diretamente causando um XSS
            // sem realmente definir um setter poluído no protótipo.
            // A verificação simples obj.innerHTML === pollutedValue pode não ser significativa aqui.
            if (Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')?.value === pollutedValue) {
                return "A propriedade 'value' do descritor de Element.prototype.innerHTML foi poluída (altamente improvável para setters/getters nativos).";
            }
            return null;
          }
        },
         { name: 'customDataProp', proto: Node.prototype, protoName: 'Node', createTarget: () => document.createElement('div'),
          gadgetCheck: (obj, pollutedValue) => obj.customDataProp === pollutedValue ? 'Node.prototype.customDataProp poluído!' : null },


        // Array.prototype - Evitar sobrescrever métodos nativos se possível, ou ser muito cuidadoso.
        { name: 'customArrayProp', proto: Array.prototype, protoName: 'Array', createTarget: () => [],
          gadgetCheck: (obj, pollutedValue) => obj.customArrayProp === pollutedValue ? 'Array.prototype.customArrayProp poluído!' : null },
        { name: 'map', proto: Array.prototype, protoName: 'Array', createTarget: () => [],
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.map === pollutedValue) {
                 try { obj.map(x=>x); return "Array.map sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Array.map sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},
        // ... outros métodos de Array (filter, forEach, join) com gadgetCheck similar ao de map

        // Function.prototype
        { name: 'customFuncProp', proto: Function.prototype, protoName: 'Function', createTarget: () => function f(){},
          gadgetCheck: (obj, pollutedValue) => obj.customFuncProp === pollutedValue ? 'Function.prototype.customFuncProp poluído!' : null },
        { name: 'call', proto: Function.prototype, protoName: 'Function', createTarget: () => function f(){},
          gadgetCheck: (obj, pollutedValue) => {
            if (obj.call === pollutedValue) {
                 try { obj.call(null); return "Function.call sobrescrito, mas ainda chamável (improvável se poluído com string)"; }
                 catch(e) { return `Function.call sobrescrito e quebrou ao ser chamado! (${e.message})`; }
            } return null;
          }},
        // ... apply com gadgetCheck similar ao de call
    ];

    const testValue = "PP_S2_Refined_" + Date.now();
    let successCount = 0;
    let gadgetCount = 0;
    let gadgetMessages = [];

    for (const item of propsToPollute) {
        if (!item.proto) {
            logS2(`AVISO: Protótipo não definido para ${item.name} em testAdvancedPPS2. Pulando.`, 'warn', FNAME);
            continue;
        }
        const prop = item.name;
        const targetProto = item.proto;
        const targetProtoName = item.protoName;

        let originalDescriptor = undefined; // Usar descritor para restauração mais precisa
        let wasDefined = false;
        let pollutionAttempted = false;

        try {
            originalDescriptor = Object.getOwnPropertyDescriptor(targetProto, prop);
            if (originalDescriptor) {
                wasDefined = true;
            }
        } catch (e) {
            logS2(`AVISO: Erro ao obter descritor original de ${targetProtoName}.${prop}: ${e.message}.`, 'warn', FNAME);
            // Para protótipos DOM, isso ainda pode ser problemático.
        }

        try {
            // Lógica de poluição: usar Object.defineProperty para mais controle,
            // especialmente se a propriedade original for um acessador.
            // Se item.polluteLogic existir, usa-o.
            if (item.polluteLogic && typeof item.polluteLogic === 'function') {
                item.polluteLogic(targetProto, prop, testValue);
            } else {
                // Poluição simples (pode falhar para acessadores DOM)
                // Para evitar "Illegal invocation" ao tentar poluir propriedades como innerHTML diretamente no protótipo,
                // é mais seguro testar com propriedades customizadas ou setters/getters definidos por nós.
                // A poluição de acessadores nativos DOM no protótipo é muito complexa e específica do navegador.
                if (prop === 'innerHTML' || prop === 'outerHTML' || prop === 'textContent' || prop === 'href' || prop === 'src' || prop === 'style' || prop === 'value') {
                    logS2(`INFO: Poluição direta de protótipo DOM para '${prop}' é complexa e pulada neste refinamento. Testando em instância se possível.`, 'info', FNAME);
                } else {
                    Object.defineProperty(targetProto, prop, {
                        value: testValue,
                        writable: true,
                        configurable: true,
                        enumerable: wasDefined ? originalDescriptor.enumerable : true
                    });
                }
            }
            pollutionAttempted = true;

            let obj;
            if (item.createTarget) {
                try { obj = item.createTarget(); }
                catch (e) {
                    logS2(`AVISO: Falha ao criar objeto alvo para ${targetProtoName}.${prop}: ${e.message}`, 'warn', FNAME);
                    obj = {}; // Fallback
                }
            } else {
                obj = {};
            }

            let inheritedValue = undefined;
            let checkSuccessful = false;

            if (item.checkLogic && typeof item.checkLogic === 'function') {
                checkSuccessful = item.checkLogic(obj, prop, testValue);
            } else {
                try {
                    inheritedValue = obj[prop];
                    if (inheritedValue === testValue) {
                        checkSuccessful = true;
                    }
                } catch (e) {
                    logS2(`AVISO: Erro ao acessar ${prop} no objeto de teste para ${targetProtoName} após poluição: ${e.message}`, 'warn', FNAME);
                }
            }


            if (checkSuccessful) {
                logS2(`-> VULN: Herança/Efeito PP para '${targetProtoName}.${prop}' OK (valor = testValue ou checkLogic passou).`, 'vuln', FNAME);
                successCount++;

                if (item.gadgetCheck) {
                    let gadgetMsg = null;
                    try {
                        gadgetMsg = item.gadgetCheck(obj, testValue);
                    } catch(e){
                        gadgetMsg = `Erro ao executar gadgetCheck para ${prop}: ${e.message}`;
                    }
                    if (gadgetMsg) {
                        logS2(`-> GADGET? ${gadgetMsg}`, 'critical', FNAME);
                        gadgetMessages.push(`${prop}: ${gadgetMsg}`);
                        gadgetCount++;
                        const dangerousProps = ['constructor', '__proto__', 'hasOwnProperty', 'appendChild', 'addEventListener', 'map', 'call', 'apply'];
                        if (dangerousProps.includes(prop)) {
                            logS2(` ---> *** ALERTA: Potencial Gadget PP perigoso detectado para '${prop}'! ***`, 'escalation', FNAME);
                        }
                    }
                }
            } else if (pollutionAttempted) {
                logS2(`-> FAIL/INFO: Poluição de '${targetProtoName}.${prop}' tentada. Verificação de herança/efeito falhou. ` +
                      `Valor na instância: ${String(inheritedValue).substring(0,100)}`, 'good', FNAME);
            }

        } catch (e) {
            // Este catch captura erros durante a tentativa de poluição ou criação do objeto de teste.
            logS2(`Erro principal ao poluir/testar '${targetProtoName}.${prop}': ${e.message}`, 'error', FNAME);
             // Se a poluição em si falhou (ex: "Illegal invocation" ao definir no protótipo DOM),
             // a restauração ainda tentará usar o originalDescriptor.
        } finally {
            if (pollutionAttempted) { // Só restaura se a poluição foi tentada
                try {
                    if (wasDefined && originalDescriptor) {
                        Object.defineProperty(targetProto, prop, originalDescriptor);
                    } else if (!wasDefined && pollutionAttempted) { // Se não era definido antes, deleta
                        delete targetProto[prop];
                    }
                    // Adicionar verificação de restauração se necessário
                } catch (e) {
                    logS2(`AVISO CRÍTICO: Erro INESPERADO ao limpar/restaurar ${targetProtoName}.${prop}: ${e.message}`, 'critical', FNAME);
                }
            }
        }
        await PAUSE_S2(10);
    }

    logS2(`--- Teste PP Avançado (Refinado) Concluído (${successCount} poluições/efeitos verificados, ${gadgetCount} gadgets potenciais) ---`, 'test', FNAME);
    if (gadgetCount > 0) {
        logS2(`Resumo dos Gadgets Potenciais Detectados:`, 'critical', FNAME);
        gadgetMessages.forEach(msg => logS2(`  - ${msg}`, 'critical', FNAME));
    }
    await PAUSE_S2();
}
