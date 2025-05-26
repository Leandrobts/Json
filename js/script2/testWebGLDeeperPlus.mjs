// js/script2/testWebGLDeeperPlus.mjs
import { logS2, PAUSE_S2 } from './s2_utils.mjs';
import { getInteractiveCanvasS2 } from '../dom_elements.mjs';
import { getGlContextS2, getIsWebGL2S2, getCanvasContext2D_S2 } from '../state.mjs'; // Para usar o contexto WebGL e 2D existentes

export async function testWebGLDeeperPlusS2() {
    const FNAME = 'testWebGLDeeperPlusS2';
    const gl = getGlContextS2(); // Pega o contexto WebGL do estado (definido por testWebGLCheckS2)
    const isWebGL2 = getIsWebGL2S2();
    const canvasElementS2 = getInteractiveCanvasS2();
    const ctxS2 = getCanvasContext2D_S2(); // Pega o contexto 2D para desenhar a textura de exemplo

    if(!gl || !canvasElementS2){ 
        logS2("--- Teste: WebGL Deep Plus Pulado (WebGL N/A ou Canvas não encontrado) ---",'test', FNAME); 
        return; 
    } 
    logS2(`--- Teste: WebGL Deep Plus c/ Checks (${isWebGL2?'WebGL2':'WebGL1'}) ---`,'test', FNAME); 
    
    let pgm=null, buf=null, vs=null, fs=null, tex=null; 
    let step='init'; 
    let glError = gl.NO_ERROR; 
    const errors = []; 
    
    const checkGLError=(s)=>{ 
        let foundError = false; 
        // eslint-disable-next-line no-constant-condition
        while(true) {
            glError = gl.getError();
            if (glError === gl.NO_ERROR) break;
            
            let errorString = `GL Unknown Error ${glError}`; 
            for(let key in gl) { 
                try{ if(gl[key] === glError) { errorString = key; break; }} catch(e){} 
            } 
            const eStr=`GL Err ${errorString} (0x${glError.toString(16)}) after ${s}`; 
            logS2(eStr,'error', FNAME); 
            errors.push(eStr); 
            foundError = true; 
        }
        return !foundError; // Retorna true se NÃO houver erro
    }; 
    
    try {
        checkGLError('initial state'); // Limpa quaisquer erros pendentes
        step='compileShaders'; 
        const vsSrc=`attribute vec4 p; void main(){ gl_Position = vec4(p.xy * 0.5 - 0.5, 0.0, 1.0); }`; // Ajustado para desenhar no canto
        const fsSrc=`precision mediump float; uniform sampler2D u_tex; void main(){ gl_FragColor = texture2D(u_tex, vec2(gl_FragCoord.x / 50.0, gl_FragCoord.y / 50.0)) * vec4(1.0, ${isWebGL2 ? '0.5' : '0.0'}, 0.0, 1.0); }`; // Usa gl_FragCoord para variar a cor
        
        vs=gl.createShader(gl.VERTEX_SHADER); 
        if(!vs || !checkGLError('createShader(VS)')) throw new Error('Falha criar VS'); 
        gl.shaderSource(vs,vsSrc); 
        if(!checkGLError('shaderSource(VS)')) throw new Error('Falha source VS'); 
        gl.compileShader(vs); 
        if(!checkGLError('compileShader(VS)')) {} // Loga o erro mas não necessariamente lança
        if(!gl.getShaderParameter(vs,gl.COMPILE_STATUS)){ 
            const infoLog = gl.getShaderInfoLog(vs); 
            logS2(`Erro Compilar VS: ${infoLog}`, 'error', FNAME); 
            throw new Error(`VS Compile: ${infoLog}`); 
        } 
        
        fs=gl.createShader(gl.FRAGMENT_SHADER); 
        if(!fs || !checkGLError('createShader(FS)')) throw new Error('Falha criar FS'); 
        gl.shaderSource(fs,fsSrc); 
        if(!checkGLError('shaderSource(FS)')) throw new Error('Falha source FS'); 
        gl.compileShader(fs); 
        if(!checkGLError('compileShader(FS)')) {}
        if(!gl.getShaderParameter(fs,gl.COMPILE_STATUS)){ 
            const infoLog = gl.getShaderInfoLog(fs); 
            logS2(`Erro Compilar FS: ${infoLog}`, 'error', FNAME); 
            throw new Error(`FS Compile: ${infoLog}`); 
        } 
        
        step='linkProgram'; 
        pgm=gl.createProgram(); 
        if(!pgm || !checkGLError('createProgram')) throw new Error('Falha createProgram'); 
        gl.attachShader(pgm,vs); 
        if(!checkGLError('attachVS')) throw new Error('Falha attachVS'); 
        gl.attachShader(pgm,fs); 
        if(!checkGLError('attachFS')) throw new Error('Falha attachFS'); 
        gl.linkProgram(pgm); 
        if(!checkGLError('linkProgram')) {}
        if(!gl.getProgramParameter(pgm,gl.LINK_STATUS)){ 
            const infoLog = gl.getProgramInfoLog(pgm); 
            logS2(`Erro Linkar Programa: ${infoLog}`, 'error', FNAME); 
            throw new Error(`Link: ${infoLog}`); 
        } 
        gl.useProgram(pgm); 
        if(!checkGLError('useProgram')) throw new Error('Falha useProgram'); 
        
        step='textureSetup'; 
        tex=gl.createTexture(); 
        if(!tex || !checkGLError('createTexture')) throw new Error('Falha createTexture'); 
        gl.bindTexture(gl.TEXTURE_2D,tex); 
        if(!checkGLError('bindTexture')) throw new Error('Falha bindTexture'); 
        
        // Desenha algo no canvas 2D para usar como textura
        if(ctxS2){ 
            ctxS2.save(); 
            ctxS2.fillStyle='lime'; 
            ctxS2.fillRect(50, canvasElementS2.height - 50, 40, 40); // Perto da área do WebGL
            ctxS2.fillStyle='black'; 
            ctxS2.font='bold 12px mono'; 
            ctxS2.fillText('TEX', 55, canvasElementS2.height - 30); 
            ctxS2.restore(); 
        } 
        await PAUSE_S2(20); 
        
        // Usa o próprio canvas 2D como fonte para a textura WebGL
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, canvasElementS2); 
        if(!checkGLError('texImage2D')) throw new Error('Falha texImage2D'); 
        gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MAG_FILTER,gl.NEAREST); 
        checkGLError('texParamMag');
        gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MIN_FILTER,gl.NEAREST); 
        checkGLError('texParamMin');
        gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_S,gl.CLAMP_TO_EDGE); 
        checkGLError('texParamWrapS');
        gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_T,gl.CLAMP_TO_EDGE); 
        checkGLError('texParamWrapT');
        
        step='uniformTex'; 
        const texLoc = gl.getUniformLocation(pgm, 'u_tex'); 
        if(!checkGLError('getUniLocTex')) {}
        if(texLoc){ 
            gl.uniform1i(texLoc, 0); // Textura unit 0
            if(!checkGLError('uniform1i')) throw new Error('Falha uniform1i'); 
        } else {
            logS2("AVISO: Uniform u_tex não encontrado no shader.", "warn", FNAME);
        }
        
        step='createBufferDraw'; 
        buf=gl.createBuffer(); 
        if(!buf || !checkGLError('createBuf')) throw new Error('Falha createBuf'); 
        gl.bindBuffer(gl.ARRAY_BUFFER,buf); 
        if(!checkGLError('bindBuf')) throw new Error('Falha bindBuf'); 
        const pos=new Float32Array([-1,-1, 1,-1, -1,1, -1,1, 1,-1, 1,1]); // Dois triângulos para um quadrado
        gl.bufferData(gl.ARRAY_BUFFER, pos, gl.STATIC_DRAW); 
        if(!checkGLError('bufData')) throw new Error('Falha bufData'); 
        
        step='vertexAttrib'; 
        const loc=gl.getAttribLocation(pgm,"p"); 
        if (loc < 0) { 
            checkGLError('getAttribLoc(p)'); 
            throw new Error("Atributo 'p' não encontrado no shader."); 
        } 
        checkGLError('getAttribLoc(p)');
        gl.enableVertexAttribArray(loc); 
        if(!checkGLError('enableVA')) throw new Error('Falha enableVA'); 
        gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0); 
        if(!checkGLError('vertexAttribPtr')) throw new Error('Falha vertexAttribPtr'); 
        
        step='draw'; 
        // Define o viewport para uma pequena área no canto inferior esquerdo do canvas 2D
        const glViewportX = 0; 
        const glViewportY = 0; // GL Y=0 é embaixo
        const glViewportW = 50; 
        const glViewportH = 50; 
        gl.viewport(glViewportX, glViewportY, glViewportW, glViewportH); 
        if(!checkGLError('viewport')) throw new Error('Falha viewport'); 
        
        gl.clearColor(0.1, 0.1, 0.2, 1.0); 
        if(!checkGLError('clearColor')) throw new Error('Falha clearColor'); 
        gl.clear(gl.COLOR_BUFFER_BIT); 
        if(!checkGLError('clear')) throw new Error('Falha clear'); 
        
        gl.activeTexture(gl.TEXTURE0); 
        if(!checkGLError('activeTex')) throw new Error('Falha activeTex'); 
        gl.bindTexture(gl.TEXTURE_2D, tex); 
        if(!checkGLError('bindTexDraw')) throw new Error('Falha bindTexDraw'); 
        
        gl.drawArrays(gl.TRIANGLES, 0, 6); // 6 vértices para 2 triângulos
        if(!checkGLError('drawArrays')) { 
            logS2("drawArrays executado sem erros GL imediatos.", 'good', FNAME); 
        } else { 
            throw new Error('Erro GL após drawArrays'); 
        } 
        
        if(errors.length === 0){ 
            logS2("Sequência WebGL básica concluída sem erros GL.", 'good', FNAME); 
        } else {
            logS2(`Sequência WebGL concluída com ${errors.length} erros GL.`, 'warn', FNAME);
        }
        
    } catch(e){ 
        logS2(`Erro fatal WebGL Deep Plus (etapa ${step}): ${e.message}`,'error', FNAME); 
        console.error(e); 
        checkGLError(`error_catch_${step}`); // Tenta logar qualquer erro GL pendente
    } finally { 
        // Limpeza de recursos WebGL
        if(gl){ 
            try{gl.bindBuffer(gl.ARRAY_BUFFER,null);}catch(e){} 
            try{gl.bindTexture(gl.TEXTURE_2D,null);}catch(e){} 
            try{gl.useProgram(null);}catch(e){} 
            if(pgm && vs){try{gl.detachShader(pgm, vs);}catch(e){}} 
            if(pgm && fs){try{gl.detachShader(pgm, fs);}catch(e){}} 
            if(vs){try{gl.deleteShader(vs);}catch(e){}} 
            if(fs){try{gl.deleteShader(fs);}catch(e){}} 
            if(pgm){try{gl.deleteProgram(pgm);}catch(e){}} 
            if(buf){try{gl.deleteBuffer(buf);}catch(e){}} 
            if(tex){try{gl.deleteTexture(tex);}catch(e){}} 
            
            // Restaura o viewport para o tamanho total do canvas se for usado por outros testes 2D depois
            // gl.viewport(0, 0, gl.canvas.width, gl.canvas.height);
        } 
    } 
    logS2("--- Teste WebGL Deep Plus Concluído ---",'test', FNAME); 
    await PAUSE_S2();
}
