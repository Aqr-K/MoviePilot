import{b as e,__mp_tla as __mp_tla_0}from"./date-OIgW8uJy.js";import{u as n,__mp_tla as __mp_tla_1}from"./usePagePresentationMotion-CFADOpwu.js";import{bg as t,bh as r,bi as a,bj as i,Y as o,bk as l,bl as u,bm as s,bn as c,bo as d,bp as f,bq as p,br as m,bs as v,bt as h,bu as g,bv as x,bw as w,bx as y,by as S,bz as T,bA as M,bB as b,bC as D,bD as P,bE as E,bF as R,bG as W,bH as k,__mp_tla as __mp_tla_2}from"./index-DV0RKR2e.js";let de;let __mp_tla=Promise.all([(()=>{try{return __mp_tla_0}catch{}})(),(()=>{try{return __mp_tla_1}catch{}})(),(()=>{try{return __mp_tla_2}catch{}})()]).then(async()=>{const{nextTick:A,onScopeDispose:L,ref:F,toValue:C,watch:U}=await e("vue");function z(){const e=new Map;return{get(n,t){const r=e.get(n);if(r)return e.delete(n),e.set(n,r),r;const a=t();for(e.set(n,a);e.size>3;){const n=e.keys().next().value;n&&e.delete(n)}return a.catch((()=>{e.get(n)===a&&e.delete(n)})),a}}}function H(e,n){e.value=n,document.documentElement.dataset.glassRendererState=n}function V(){const e={fixed:new Set,scroll:new Set},n=new Map,t=(e,n)=>{if(document.querySelector(".v-overlay--active"))return null;const t=document.querySelector(".login-card");if(t){const r=t.getBoundingClientRect();if(e>=r.left&&e<=r.right&&n>=r.top&&n<=r.bottom)return document.querySelector(".login-root")?"scroll":"fixed"}const r=document.querySelectorAll(".agent-assistant-panel, .layout-navbar, .layout-vertical-nav");for(const a of r){const t=a.getBoundingClientRect();if(e>=t.left&&e<=t.right&&n>=t.top&&n<=t.bottom)return"fixed"}return"scroll"},r=e=>e.type.startsWith("touch"),a=a=>{const i=r(a)?(e=>{const r=e.changedTouches.item(0);if(!r)return null;if("touchstart"===e.type){const e=t(r.clientX,r.clientY);return e&&n.set(r.identifier,e),e}return n.get(r.identifier)??null})(a):t(a.clientX,a.clientY);if(i){for(const n of e[i])n(a);if(r(a)&&("touchend"===a.type||"touchcancel"===a.type))for(const e of Array.from(a.changedTouches))n.delete(e.identifier)}};return window.addEventListener("pointermove",a,{passive:!0}),window.addEventListener("touchstart",a,{passive:!0}),window.addEventListener("touchmove",a,{passive:!0}),window.addEventListener("touchend",a,{passive:!0}),window.addEventListener("touchcancel",a,{passive:!0}),L((()=>{e.fixed.clear(),e.scroll.clear(),n.clear(),window.removeEventListener("pointermove",a),window.removeEventListener("touchstart",a),window.removeEventListener("touchmove",a),window.removeEventListener("touchend",a),window.removeEventListener("touchcancel",a)})),{subscribe:(n,t)=>(e[n].add(t),()=>e[n].delete(t))}}const B=[{rank:1,selector:".agent-assistant-panel",space:"fixed"},{rank:1,selector:".login-card",space:"fixed"},{rank:2,selector:".layout-vertical-nav",space:"fixed"},{rank:2,selector:".layout-navbar",space:"fixed"},{rank:3,selector:".dashboard-grid-item-content > .dashboard-grid-auto-size > .dashboard-grid-content-measure > .v-card",space:"scroll"},{rank:3,selector:".dashboard-grid-item-content > .dashboard-grid-auto-size > .dashboard-grid-content-measure > :first-child > .v-card",space:"scroll"},{rank:3,selector:"[data-glass-optical-surface]",space:"scroll"},{rank:4,selector:".app-hover-lift-card",space:"scroll"},{rank:5,selector:".layout-page-content .v-card",space:"scroll"}],q=B.map((({selector:e})=>e)).join(","),I=".app-hover-lift-card";function O(e,n){return".login-card"===e&&document.querySelector(".login-root")?"scroll":n}function K(e){return e instanceof Element&&(!(!e.matches(q)||e.closest(".v-overlay"))||Array.from(e.querySelectorAll(q)).some((e=>!e.closest(".v-overlay"))))}const Q="\nvarying vec2 vUv;\n\nvoid main() {\n  vUv = position.xy * 0.5 + 0.5;\n  gl_Position = vec4(position.xy, 0.0, 1.0);\n}\n",$=1/.4**2,G=`
precision highp float;

uniform sampler2D uPrevious;
uniform vec2 uPointer;
uniform vec2 uVelocity;
uniform vec2 uTexelSize;
uniform float uInjection;
uniform float uDecay;
uniform float uViewportAspect;
varying vec2 vUv;

void main() {
  vec4 previous = (
    texture2D(uPrevious, vUv) * 0.5 +
    texture2D(uPrevious, vUv + vec2(uTexelSize.x, 0.0)) * 0.125 +
    texture2D(uPrevious, vUv - vec2(uTexelSize.x, 0.0)) * 0.125 +
    texture2D(uPrevious, vUv + vec2(0.0, uTexelSize.y)) * 0.125 +
    texture2D(uPrevious, vUv - vec2(0.0, uTexelSize.y)) * 0.125
  );
  float previousEnergy = previous.z;
  vec2 flow = previousEnergy < 0.001 ? vec2(0.0) : (previous.xy * 2.0 - 1.0) * uDecay;
  float energy = previousEnergy * uDecay;
  vec2 delta = vUv - uPointer;
  delta.x *= uViewportAspect;
  float distanceSquared = dot(delta, delta);
  float injection = exp(-distanceSquared * ${(70*$).toFixed(3)}) * uInjection;
  float speed = length(uVelocity);
  vec2 direction = speed > 0.0001 ? uVelocity / speed : vec2(0.0, -1.0);
  vec2 perpendicular = vec2(-direction.y, direction.x);
  float shear = dot(delta, perpendicular) * exp(-distanceSquared * ${(42*$).toFixed(3)});

  flow += (direction * min(speed * 9.0, 0.9) - perpendicular * shear * 0.85) * injection * 0.44;
  energy = max(energy, injection);

  gl_FragColor = vec4(flow * 0.5 + 0.5, energy, 1.0);
}
`;function Y(e,n,t,r,o=window.location.href){const l=a(n,t),u="auto"===l.textureSource?i(r,o)?"wallpaper":"procedural":l.textureSource;return`${"frosted"===e?"frosted":"plain"}:${n}:${l.textureLimit}:${u}`}const _=`
precision highp float;

uniform sampler2D uPreviousTexture;
uniform sampler2D uTexture;
uniform sampler2D uPreviousFrostedTexture;
uniform sampler2D uFrostedTexture;
uniform sampler2D uFlowTexture;
uniform vec2 uCoverScale;
uniform vec2 uPreviousCoverScale;
uniform vec2 uPresentationSize;
uniform vec2 uScrollOffset;
uniform vec2 uVisibleViewportSize;
uniform float uDeformationStrength;
uniform float uDynamicsOnly;
uniform float uFlowStrength;
uniform float uHasWallpaperTexture;
uniform float uHasFlowTexture;
uniform float uHasFrostedTexture;
uniform vec4 uInteractionRadii[8];
uniform vec4 uInteractionRects[8];
uniform int uInteractionRectCount;
uniform float uMotion;
uniform float uMotionExpansion;
uniform float uMaxRefractionPixels;
uniform vec2 uPointer;
uniform vec2 uPointerVelocity;
uniform vec2 uWakeDirection;
uniform float uQuality;
uniform float uReflectionStrength;
uniform vec4 uRects[8];
uniform vec4 uRadii[8];
uniform float uSurfaceWeights[8];
uniform float uSurfaceDynamics[8];
uniform int uRectCount;
uniform float uAppearance;
uniform float uBackgroundVisibility;
uniform vec3 uTintColor;
uniform float uFrostDetailLevel;
uniform float uSurfaceDensity;
uniform float uTintDensity;
uniform float uTransmissionStrength;
uniform float uTranslationStrength;
uniform float uTextureMix;
uniform float uPreviousWallpaperExposure;
uniform float uWallpaperExposure;
uniform vec4 uTrail[4];
uniform int uTrailCount;
varying vec2 vUv;

float cornerRadius(vec2 centered, vec4 radii) {
  if (centered.x >= 0.0) return centered.y >= 0.0 ? radii.y : radii.z;

  return centered.y >= 0.0 ? radii.x : radii.w;
}

float roundedRectMask(vec2 local, vec2 rectSize, vec4 radii) {
  vec2 localPixels = (local - 0.5) * rectSize;
  float radius = cornerRadius(localPixels, radii);
  float safeRadius = min(max(radius, 0.0), min(rectSize.x, rectSize.y) * 0.5);
  vec2 centered = abs(localPixels) - (rectSize * 0.5 - vec2(safeRadius));
  float distanceToEdge = length(max(centered, 0.0)) + min(max(centered.x, centered.y), 0.0) - safeRadius;
  return 1.0 - smoothstep(0.0, 1.5, distanceToEdge);
}

vec2 coverUv(vec2 uv) {
  vec2 documentPixels = vec2(uv.x, 1.0 - uv.y) * uPresentationSize;
  vec2 viewportPixels = documentPixels - uScrollOffset;
  vec2 viewportUv = vec2(
    viewportPixels.x / max(uVisibleViewportSize.x, 1.0),
    1.0 - viewportPixels.y / max(uVisibleViewportSize.y, 1.0)
  );

  return vec2(0.5) + (viewportUv - vec2(0.5)) * uCoverScale;
}

vec3 compressWallpaperLuminance(vec3 color, float wallpaperExposure) {
  vec3 exposed = max(color * wallpaperExposure, vec3(0.0));
  float sourceLuminance = dot(exposed, vec3(0.2126, 0.7152, 0.0722));
  if (sourceLuminance <= 0.0001) return exposed;

  float shadowLift = (1.0 - smoothstep(0.06, 0.5, sourceLuminance)) * 0.22;
  float highlightCompression = smoothstep(0.72, 0.98, sourceLuminance) * 0.08;
  float compressedLuminance =
    sourceLuminance * (1.0 + shadowLift) * (1.0 - highlightCompression);

  return clamp(exposed * (compressedLuminance / sourceLuminance), 0.0, 1.0);
}

vec3 toneMapWallpaper(vec3 color, vec2 uv, float wallpaperExposure) {
  float tinted = step(0.5, uAppearance) * (1.0 - step(1.5, uAppearance));
  float frosted = step(1.5, uAppearance);
  float exposure = mix(0.86, 0.85, tinted);
  exposure = mix(exposure, 0.82, frosted);
  float saturation = mix(0.82, 0.95, tinted);
  saturation = mix(saturation, 0.9, frosted);
  float contrast = mix(1.02, 1.0, frosted);
  vec3 normalized = compressWallpaperLuminance(color, wallpaperExposure);
  float luminance = dot(normalized, vec3(0.2126, 0.7152, 0.0722));
  vec3 mapped = mix(vec3(luminance), normalized, saturation);
  mapped = clamp((mapped - vec3(0.5)) * contrast + vec3(0.5), 0.0, 1.0) * exposure;

  float top = 1.0 - uv.y;
  float linearStart = mix(0.1, 0.24, frosted);
  float linearEnd = mix(mix(0.3, 0.32, tinted), 0.48, frosted);
  float linearAbsorption = mix(linearStart, linearEnd, top);
  vec2 radialDelta = (uv - vec2(0.5, 0.82)) / vec2(0.78, 1.0);
  float radialAbsorption = smoothstep(0.24, 0.92, length(radialDelta)) * mix(0.12, 0.14, tinted);
  radialAbsorption *= 1.0 - frosted;
  vec3 absorbed = mapped * (1.0 - linearAbsorption) * (1.0 - radialAbsorption);
  float transmissionResponse =
    pow(clamp(uTransmissionStrength, 0.0, 1.0), mix(0.9, 0.78, uQuality));
  float referenceLiftProgress = smoothstep(0.7, 1.0, uTransmissionStrength);
  float highTransmissionProgress =
    clamp((uTransmissionStrength - 1.0) / 0.3, 0.0, 1.0);
  float transmissionMaterialScale = mix(1.0, 0.9, tinted);
  float frostedTransparencyProgress =
    smoothstep(0.6, 0.96, uBackgroundVisibility);
  float frostedTransmissionScale = mix(0.42, 0.72, frostedTransparencyProgress);
  transmissionMaterialScale = mix(transmissionMaterialScale, frostedTransmissionScale, frosted);
  float highlightProtection = smoothstep(0.68, 0.92, luminance);
  vec3 transmissionReference = normalized;
  float referenceLift =
    transmissionMaterialScale *
    (
      referenceLiftProgress * mix(0.18, 0.25, uQuality) +
      highTransmissionProgress * mix(0.1, 0.16, uQuality)
    );
  transmissionReference *= 1.0 + referenceLift * (1.0 - highlightProtection * 0.72);
  transmissionReference = min(transmissionReference, vec3(0.96));
  vec3 protectedHighlightReference = min(normalized, vec3(0.96));
  transmissionReference = mix(
    transmissionReference,
    protectedHighlightReference,
    highlightProtection * 0.78
  );
  float transmissionMix = min(
    transmissionResponse *
      transmissionMaterialScale *
      mix(0.58, 0.84, uQuality),
    0.84
  );

  return mix(absorbed, transmissionReference, transmissionMix);
}

vec3 sampleWallpaper(vec2 uv) {
  vec2 viewportUv = vec2(0.5) + (uv - vec2(0.5)) / max(uCoverScale, vec2(0.0001));
  vec2 previousUv = vec2(0.5) + (viewportUv - vec2(0.5)) * uPreviousCoverScale;
  vec3 previous;
  vec3 current;
  if (uAppearance > 1.5 && uHasFrostedTexture > 0.5) {
    float frostLod = (1.0 - uFrostDetailLevel) * 6.0;
    // 低分辨率预滤已经扩大了每个 texel 的原图 footprint，LOD 只追加当前纹理内的低通层级。
    float frostGradientScale = exp2(frostLod);
    previous = texture2DGradEXT(
      uPreviousFrostedTexture,
      previousUv,
      dFdx(previousUv) * frostGradientScale,
      dFdy(previousUv) * frostGradientScale
    ).rgb;
    current = texture2DGradEXT(
      uFrostedTexture,
      uv,
      dFdx(uv) * frostGradientScale,
      dFdy(uv) * frostGradientScale
    ).rgb;
  } else {
    previous = texture2D(uPreviousTexture, previousUv).rgb;
    current = texture2D(uTexture, uv).rgb;
  }

  if (uTextureMix <= 0.001) {
    return toneMapWallpaper(previous, viewportUv, uPreviousWallpaperExposure);
  }
  if (uTextureMix >= 0.999) {
    return toneMapWallpaper(current, viewportUv, uWallpaperExposure);
  }

  vec3 previousTone = toneMapWallpaper(previous, viewportUv, uPreviousWallpaperExposure);
  vec3 currentTone = toneMapWallpaper(current, viewportUv, uWallpaperExposure);

  return mix(previousTone, currentTone, uTextureMix);
}

vec3 sampleChromatic(vec2 uv, float separation) {
  return vec3(
    sampleWallpaper(uv + vec2(separation, 0.0)).r,
    sampleWallpaper(uv).g,
    sampleWallpaper(uv - vec2(separation, 0.0)).b
  );
}

vec3 sampleBalancedDiffuse(vec2 uv, vec2 axis, float radius) {
  vec2 firstOffset = axis * radius;
  vec2 secondOffset = vec2(-axis.y, axis.x) * radius;

  return (
    sampleWallpaper(uv) * 0.28 +
    sampleWallpaper(uv + firstOffset) * 0.18 +
    sampleWallpaper(uv - firstOffset) * 0.18 +
    sampleWallpaper(uv + secondOffset) * 0.18 +
    sampleWallpaper(uv - secondOffset) * 0.18
  );
}

vec3 sampleHighQualityDiffuse(vec2 uv, vec2 axis, float radius) {
  vec2 firstOffset = axis * radius;
  vec2 secondOffset = vec2(-axis.y, axis.x) * radius;
  vec2 firstDiagonal = normalize(firstOffset + secondOffset) * radius * 1.15;
  vec2 secondDiagonal = normalize(firstOffset - secondOffset) * radius * 1.15;

  return (
    sampleWallpaper(uv) * 0.2 +
    sampleWallpaper(uv + firstOffset) * 0.12 +
    sampleWallpaper(uv - firstOffset) * 0.12 +
    sampleWallpaper(uv + secondOffset) * 0.12 +
    sampleWallpaper(uv - secondOffset) * 0.12 +
    sampleWallpaper(uv + firstDiagonal) * 0.08 +
    sampleWallpaper(uv - firstDiagonal) * 0.08 +
    sampleWallpaper(uv + secondDiagonal) * 0.08 +
    sampleWallpaper(uv - secondDiagonal) * 0.08
  );
}

float getContentProtection(vec2 sourceUv) {
  if (uQuality < 0.5 || uHasWallpaperTexture < 0.5 || uAppearance > 1.5) return 1.0;

  vec2 sourceTexel = max(uCoverScale, vec2(0.0001)) / max(uVisibleViewportSize, vec2(1.0));
  vec3 horizontalStart = sampleWallpaper(sourceUv - vec2(sourceTexel.x * 2.5, 0.0));
  vec3 horizontalEnd = sampleWallpaper(sourceUv + vec2(sourceTexel.x * 2.5, 0.0));
  vec3 verticalStart = sampleWallpaper(sourceUv - vec2(0.0, sourceTexel.y * 2.5));
  vec3 verticalEnd = sampleWallpaper(sourceUv + vec2(0.0, sourceTexel.y * 2.5));
  float contentGradient = max(length(horizontalEnd - horizontalStart), length(verticalEnd - verticalStart));

  return mix(1.0, 0.44, smoothstep(0.07, 0.34, contentGradient));
}

vec2 softLimitDynamicRefraction(vec2 refraction) {
  vec2 presentation = max(uPresentationSize, vec2(1.0));
  vec2 refractionPixels = refraction * presentation;
  float limit = max(0.5, uMaxRefractionPixels);
  float limitScale = limit / sqrt(limit * limit + dot(refractionPixels, refractionPixels));

  return refractionPixels * limitScale / presentation;
}

void main() {
  float mask = 0.0;
  float edge = 0.0;
  float caustic = 0.0;
  float directionalReflection = 0.0;
  float topPrism = 0.0;
  float backlightAbsorption = 0.0;
  float materialEnergy = 0.0;
  float sharedMotionPresence = 0.0;
  float dynamicMask = 0.0;
  vec2 staticRefraction = vec2(0.0);
  vec2 dynamicRefraction = vec2(0.0);
  vec2 wakeDirection = length(uWakeDirection) > 0.0001 ? normalize(uWakeDirection) : vec2(0.0, -1.0);
  vec2 wakePerpendicular = vec2(-wakeDirection.y, wakeDirection.x);
  vec2 trailRefraction = vec2(0.0);
  float trailEnergy = 0.0;
  float trailSpatialSpan = 0.0;
  float motionRangeCompression = mix(1.0, 1.34, uMotionExpansion);
  const float dynamicRangeScale = ${.4.toFixed(2)};
  const float dynamicRangeDensity = ${$.toFixed(3)};
  float interactionMask = uInteractionRectCount > 0 ? 0.0 : 1.0;
  for (int interactionIndex = 0; interactionIndex < 8; interactionIndex++) {
    if (interactionIndex >= uInteractionRectCount) break;

    vec4 interactionRect = uInteractionRects[interactionIndex];
    vec2 interactionLocal = (vUv - interactionRect.xy) / max(interactionRect.zw, vec2(0.0001));
    interactionMask = max(
      interactionMask,
      roundedRectMask(
        interactionLocal,
        interactionRect.zw * uPresentationSize,
        uInteractionRadii[interactionIndex]
      )
    );
  }

  for (int trailIndex = 0; trailIndex < 4; trailIndex++) {
    if (trailIndex >= uTrailCount) break;

    vec4 trail = uTrail[trailIndex];
    vec2 trailDelta = vUv - trail.xy;
    trailDelta *= uPresentationSize / max(uVisibleViewportSize.y, 1.0) * motionRangeCompression;
    vec2 trailSpanDelta = trail.xy - uPointer;
    trailSpanDelta *= uPresentationSize / max(uVisibleViewportSize.y, 1.0) * motionRangeCompression;
    trailSpatialSpan = max(trailSpatialSpan, length(trailSpanDelta) * trail.z);
    float along = dot(trailDelta, wakeDirection);
    float across = dot(trailDelta, wakePerpendicular);
    float trailAlongDensity = mix(42.0, 22.0, uMotionExpansion) * dynamicRangeDensity;
    float trailAcrossDensity = mix(210.0, 86.0, uMotionExpansion) * dynamicRangeDensity;
    float lobe =
      exp(-(along * along * trailAlongDensity + across * across * trailAcrossDensity)) * trail.z * uMotion;
    float wake = mix(0.88, 0.58, float(trailIndex) / 3.0);

    trailRefraction +=
      (wakeDirection * 0.0048 + wakePerpendicular * across * 0.018) *
      lobe *
      uDeformationStrength *
      uFlowStrength;
    trailEnergy += lobe * wake * mix(0.72, 0.42, float(trailIndex) / 3.0);
  }

  vec4 flowSample = uHasFlowTexture > 0.5 ? texture2D(uFlowTexture, vUv) : vec4(0.5, 0.5, 0.0, 1.0);
  vec2 temporalFlow =
    uHasFlowTexture > 0.5
      ? (flowSample.xy * 2.0 - 1.0) *
        flowSample.z *
        uMotion *
        uDeformationStrength *
        uFlowStrength
      : vec2(0.0);
  float flowSurfaceDetail = 0.0;
  if (uQuality > 0.5 && uHasFlowTexture > 0.5) {
    vec2 flowTexel = vec2(3.0) / max(uPresentationSize, vec2(1.0));
    vec3 flowLeft = texture2D(uFlowTexture, vUv - vec2(flowTexel.x, 0.0)).xyz;
    vec3 flowRight = texture2D(uFlowTexture, vUv + vec2(flowTexel.x, 0.0)).xyz;
    vec3 flowBottom = texture2D(uFlowTexture, vUv - vec2(0.0, flowTexel.y)).xyz;
    vec3 flowTop = texture2D(uFlowTexture, vUv + vec2(0.0, flowTexel.y)).xyz;
    float flowGradient = length(flowRight.xy - flowLeft.xy) + length(flowTop.xy - flowBottom.xy);
    float energyGradient = abs(flowRight.z - flowLeft.z) + abs(flowTop.z - flowBottom.z);
    flowSurfaceDetail = smoothstep(0.015, 0.24, flowGradient + energyGradient * 0.72) * uMotion;
  }
  float frosted = step(1.5, uAppearance);

  for (int i = 0; i < 8; i++) {
    if (i >= uRectCount) break;

    vec4 rect = uRects[i];
    float surfaceDynamic = uSurfaceDynamics[i];
    vec2 local = (vUv - rect.xy) / rect.zw;
    float rectMask = roundedRectMask(local, rect.zw * uPresentationSize, uRadii[i]) * uSurfaceWeights[i];
    if (rectMask <= 0.0) continue;

    float sideDistance = min(local.x, 1.0 - local.x);
    float nonBottomDistance = min(sideDistance, 1.0 - local.y);
    float edgeResponse = 1.0 - smoothstep(0.0, 0.16, nonBottomDistance);
    vec2 lens = local - vec2(0.5);
    vec2 lightDirection = normalize(vec2(-0.68, 0.74));
    float lightCoordinate = dot(lens, lightDirection);
    float broadLight =
      exp(-pow((lightCoordinate - 0.08) * 2.25, 2.0)) *
      (0.42 + edgeResponse * 0.58);
    float topEdge = 1.0 - smoothstep(0.0, 0.11, 1.0 - local.y);
    float rightEdge = 1.0 - smoothstep(0.0, 0.14, 1.0 - local.x);
    float bottomEdge = 1.0 - smoothstep(0.0, 0.14, local.y);
    float litResponse = clamp(0.5 + lightCoordinate * 1.15, 0.0, 1.0);
    float localDirectionalReflection = broadLight * mix(0.34, 1.0, litResponse) * rectMask;
    float localTopPrism = topEdge * mix(0.38, 1.0, 1.0 - local.x) * rectMask;
    float localBacklightAbsorption = max(rightEdge * 0.72, bottomEdge * 0.46) * rectMask;
    vec2 pointerDelta = uPointer - vUv;
    vec2 pointerDeltaAspect = pointerDelta;
    pointerDeltaAspect *= uPresentationSize / max(uVisibleViewportSize.y, 1.0) * motionRangeCompression;
    // 三材质共享指针几何足迹；磨砂身份由位移幅度、低通扩散和材质合成表达。
    float pointerSpread = mix(26.0, 17.0, uQuality);
    pointerSpread *= dynamicRangeDensity * mix(1.0, 0.46, uMotionExpansion);
    float sharedDirectionality = smoothstep(0.015, 0.18, trailSpatialSpan);
    float pointerAlong = dot(-pointerDeltaAspect, wakeDirection);
    float pointerAcross = dot(-pointerDeltaAspect, wakePerpendicular);
    float sharedWakeTravel =
      0.08 * sharedDirectionality * mix(0.86, 1.18, uMotionExpansion);
    float radialPointerShape = exp(-dot(pointerDeltaAspect, pointerDeltaAspect) * pointerSpread);
    float directionalPointerShape =
      exp(-(
        pow(pointerAlong + sharedWakeTravel * 0.45, 2.0) * pointerSpread * 0.72 +
        pointerAcross * pointerAcross * pointerSpread * 1.35
      ));
    float pointerEnergy =
      clamp(mix(radialPointerShape, directionalPointerShape, sharedDirectionality) * uMotion, 0.0, 1.0);
    float sharedWaveDensity = mix(2.81, 1.63, uMotionExpansion);
    float radialSharedWave =
      exp(-dot(pointerDeltaAspect, pointerDeltaAspect) * sharedWaveDensity);
    float directionalSharedWave =
      exp(-(
        pow(pointerAlong + sharedWakeTravel, 2.0) * sharedWaveDensity * 0.62 +
        pointerAcross * pointerAcross * sharedWaveDensity * 2.2
      ));
    float sharedWaveEnergy =
      mix(radialSharedWave, directionalSharedWave, sharedDirectionality) *
      clamp(length(uPointerVelocity) * 14.0 * uTranslationStrength, 0.0, 1.0) *
      mix(1.0, 0.78, sharedDirectionality) *
      uMotion *
      uMotion;
    vec2 wakeDelta = vUv - uPointer;
    wakeDelta *= uPresentationSize / max(uVisibleViewportSize.y, 1.0) * motionRangeCompression;
    float wakeAlong = dot(wakeDelta, wakeDirection);
    float wakeAcross = dot(wakeDelta, wakePerpendicular);
    float wakeTravel =
      0.014 * dynamicRangeScale *
      mix(0.82, 1.18, uQuality) *
      mix(1.0, 1.45, uMotionExpansion);
    float wakeWidth =
      mix(0.027, 0.044, uQuality) * dynamicRangeScale * mix(1.0, 1.72, uMotionExpansion);
    float wakeCoordinate = (wakeAlong + wakeTravel) / wakeWidth;
    float wakeShape = wakeCoordinate * exp(-0.5 * wakeCoordinate * wakeCoordinate);
    float wakeEnvelope =
      exp(
        -wakeAcross *
        wakeAcross *
        mix(280.0, 145.0, uQuality) *
        dynamicRangeDensity *
        mix(1.0, 0.44, uMotionExpansion)
      );
    vec2 wakeRefraction =
      wakeDirection *
      wakeShape *
      wakeEnvelope *
      mix(0.0045, 0.0075, uQuality) *
      uMotion *
      uDeformationStrength *
      uFlowStrength;
    float wakeEnergy = abs(wakeShape) * wakeEnvelope * uMotion;
    float liquidEnergy = clamp(max(
      pointerEnergy,
      max(min(1.0, trailEnergy) * 0.68, wakeEnergy * 0.82)
    ), 0.0, 1.0);
    float staticLens = 0.00008 + edgeResponse * mix(0.00045, 0.00072, uQuality);
    float pointerStrength = mix(mix(0.0055, 0.008, uQuality), mix(0.0085, 0.012, uQuality), frosted);
    float trailStrength = mix(mix(0.78, 1.08, uQuality), mix(0.96, 1.3, uQuality), frosted);
    float temporalStrength = mix(0.032, 0.042, frosted) * uQuality * (1.0 + flowSurfaceDetail * 0.5);
    vec2 specularDelta =
      vUv - (uPointer - wakeDirection * mix(0.006, 0.022, uMotionExpansion) * dynamicRangeScale);
    specularDelta *= uPresentationSize / max(uVisibleViewportSize.y, 1.0) * motionRangeCompression;
    float specularAlong = dot(specularDelta, wakeDirection);
    float specularAcross = dot(specularDelta, wakePerpendicular);
    float singleSpecular =
      exp(-(
        specularAlong * specularAlong * mix(58.0, 25.0, uMotionExpansion) * dynamicRangeDensity +
        specularAcross * specularAcross * mix(190.0, 78.0, uMotionExpansion) * dynamicRangeDensity
      )) *
      uMotion *
      mix(1.0, 1.24, uMotionExpansion);
    float localCaustic = singleSpecular * rectMask * surfaceDynamic * interactionMask;
    staticRefraction += lens * staticLens * mix(1.0, 0.72, frosted) * rectMask * surfaceDynamic;
    vec2 sampleTranslation =
      uPointerVelocity *
      mix(0.055, 0.075, uQuality) *
      uMotion *
      uTranslationStrength;
    dynamicRefraction += (
      sampleTranslation +
      // 收紧高斯半径时补偿向量峰值，避免范围缩小同时削弱用户设置的形变强度。
      pointerDelta * pointerEnergy * pointerStrength * uDeformationStrength / dynamicRangeScale +
      trailRefraction * trailStrength +
      temporalFlow * temporalStrength +
      wakeRefraction
    ) * rectMask * surfaceDynamic * interactionMask;
    edge = max(edge, edgeResponse * rectMask * surfaceDynamic);
    caustic = max(caustic, localCaustic);
    directionalReflection = max(directionalReflection, localDirectionalReflection);
    topPrism = max(topPrism, localTopPrism);
    backlightAbsorption = max(backlightAbsorption, localBacklightAbsorption);
    materialEnergy = max(materialEnergy, liquidEnergy * rectMask * surfaceDynamic * interactionMask);
    sharedMotionPresence = max(
      sharedMotionPresence,
      sharedWaveEnergy * rectMask * surfaceDynamic * interactionMask
    );
    dynamicMask = max(dynamicMask, rectMask * surfaceDynamic * interactionMask);
    mask = max(mask, rectMask);
  }

  if (mask <= 0.0) discard;

  float contentProtection = getContentProtection(coverUv(vUv + staticRefraction));
  dynamicRefraction *= contentProtection;
  // 高光足迹与壁纸位移强度独立校准，收紧反馈范围不能同步削弱三项动态参数。
  dynamicRefraction *= 1.2;
  dynamicRefraction = softLimitDynamicRefraction(dynamicRefraction);
  vec2 refraction = staticRefraction + dynamicRefraction;
  vec2 sourceUv = coverUv(vUv + refraction);
  float separation = edge * mix(0.00024, 0.00055, uQuality) * mix(1.0, 0.58, frosted);
  float usesPrefilteredFrost = frosted * uHasFrostedTexture;
  vec3 refracted = usesPrefilteredFrost > 0.5
    ? sampleWallpaper(sourceUv)
    : sampleChromatic(sourceUv, separation);
  float detailSeparation = separation * mix(1.45, 2.35, uQuality);
  vec3 detailed = usesPrefilteredFrost > 0.5
    ? refracted
    : sampleChromatic(sourceUv, detailSeparation);
  refracted = mix(refracted, detailed, mix(0.06, 0.16, uQuality) * (1.0 - frosted));
  vec2 diffusionAxis = length(refraction) > 0.00001 ? normalize(refraction) : wakePerpendicular;
  float diffusionRadius =
    mix(0.0022, 0.0038, uQuality) *
    (
      0.82 +
      materialEnergy * mix(0.28, 0.76, uMotionExpansion) +
      flowSurfaceDetail * dynamicMask * 0.38
    );
  float frostedDensity = frosted * (1.0 - uFrostDetailLevel);
  diffusionRadius *= 1.0 + frostedDensity * mix(1.15, 1.55, uQuality);
  vec3 diffused;
  if (usesPrefilteredFrost > 0.5) {
    diffused = refracted;
  } else if (uQuality > 0.5) {
    diffused = sampleHighQualityDiffuse(sourceUv, diffusionAxis, diffusionRadius);
  } else {
    diffused = sampleBalancedDiffuse(sourceUv, diffusionAxis, diffusionRadius);
  }
  refracted = mix(refracted, diffused, frosted);
  float refractedLuminance = dot(refracted, vec3(0.2126, 0.7152, 0.0722));
  float tinted = step(0.5, uAppearance) * (1.0 - step(1.5, uAppearance));
  float transmissionOffset = min(uTransmissionStrength - 1.0, 0.0);
  if (transmissionOffset < 0.0) {
    float dimming = mix(0.14, 0.18, uQuality) * mix(1.0, 0.65, frosted);
    refracted *= 1.0 + transmissionOffset * dimming;
  }
  refractedLuminance = dot(refracted, vec3(0.2126, 0.7152, 0.0722));
  float highlightBudget = mix(1.0, 0.34, smoothstep(0.48, 0.9, refractedLuminance));
  float frostedBrightCompression = smoothstep(0.58, 0.94, refractedLuminance) * frosted;
  refracted *= 1.0 - frostedBrightCompression * mix(0.16, 0.22, uQuality);
  vec3 frostedContrast = clamp((refracted - vec3(0.5)) * 1.16 + vec3(0.5), 0.0, 1.0);
  refracted = mix(
    refracted,
    frostedContrast,
    frosted * materialEnergy * mix(0.24, 0.58, uMotionExpansion)
  );
  vec3 highlight = vec3(0.84, 0.92, 1.0);
  float edgeHighlightMix = 0.12;
  float causticHighlightMix = 0.075;
  float liquidPresence = clamp(materialEnergy, 0.0, 1.0);
  float clearVisibilityProgress = clamp((uBackgroundVisibility - 0.18) / 0.78, 0.0, 1.0);
  float clearBaseAlpha = mix(0.08, 0.34, clearVisibilityProgress);
  float materialAlpha = clearBaseAlpha * mix(1.0, 2.5, liquidPresence);
  float proceduralEdgeAlpha = 0.14;
  float proceduralCausticAlpha = 0.075;

  if (uAppearance > 1.5) {
    highlight = vec3(0.94, 0.97, 1.0);
    edgeHighlightMix = 0.15;
    causticHighlightMix = 0.042;
    float frostedBaseAlpha = mix(0.46, 0.88, uSurfaceDensity);
    materialAlpha = frostedBaseAlpha * mix(0.9, 1.0, liquidPresence);
    proceduralEdgeAlpha = 0.16;
    proceduralCausticAlpha = 0.045;
  } else if (uAppearance > 0.5) {
    highlight = mix(vec3(1.0), uTintColor, mix(0.28, 0.72, uTintDensity));
    edgeHighlightMix = 0.17;
    causticHighlightMix = 0.085;
    float tintedVisibilityProgress = clamp((uBackgroundVisibility - 0.08) / 0.84, 0.0, 1.0);
    float tintedBaseAlpha = mix(0.16, 0.5, tintedVisibilityProgress);
    materialAlpha = tintedBaseAlpha * mix(1.0, 1.8, liquidPresence);
  }

  if (uHasWallpaperTexture < 0.5) {
    float proceduralReflection =
      (directionalReflection * 0.42 + topPrism * 0.66 + caustic * 0.72) *
      uReflectionStrength;
    vec3 proceduralHighlight = highlight * proceduralReflection;
    float proceduralAlpha =
      mask *
      (
        directionalReflection * proceduralEdgeAlpha +
        topPrism * proceduralEdgeAlpha * 0.76 +
        caustic * proceduralCausticAlpha
      ) *
      uReflectionStrength;
    gl_FragColor = vec4(proceduralHighlight, proceduralAlpha);
    return;
  }

  float reflectionMix =
    clamp(
      (directionalReflection * edgeHighlightMix + topPrism * edgeHighlightMix * 0.82) *
        uReflectionStrength *
        highlightBudget,
      0.0,
      0.36
    );
  float absorption =
    clamp(backlightAbsorption * mix(0.035, 0.075, frosted) * uReflectionStrength, 0.0, 0.14);
  refracted *= 1.0 - absorption;
  refracted = mix(refracted, highlight, reflectionMix);
  refracted += highlight * caustic * causticHighlightMix * uReflectionStrength * highlightBudget;

  if (uDynamicsOnly > 0.5) {
    float dynamicsPresence = max(materialEnergy, sharedMotionPresence * 0.36);
    float dynamicsAlpha =
      clamp(dynamicsPresence * mix(0.5, 0.72, uQuality) * mix(1.0, 1.12, frosted), 0.0, 0.82);
    gl_FragColor = vec4(refracted, dynamicsAlpha);
    return;
  }

  gl_FragColor = vec4(
    refracted,
    clamp(
      mask *
        (
          materialAlpha +
          (
            directionalReflection * 0.065 +
            topPrism * 0.05 +
            caustic * mix(0.028, 0.04, uQuality)
          ) *
            uReflectionStrength *
            highlightBudget
        ),
      0.0,
      0.94
    )
  );
}
`;function X(e){const n=getComputedStyle(e),t=e=>{const n=Number.parseFloat(e);return Number.isFinite(n)?n:0};return[t(n.borderTopLeftRadius),t(n.borderTopRightRadius),t(n.borderBottomRightRadius),t(n.borderBottomLeftRadius)]}function N(e,n){const t=getComputedStyle(e);return"none"!==t.display&&"hidden"!==t.visibility&&Number.parseFloat(t.opacity||"1")>0&&n.width>=24&&n.height>=24}function j(e){const n=e.closest("[data-glass-optical-mode]")?.dataset.glassOpticalMode;return"static-material"===n?"static-material":"dynamic"}function J(e){return"tinted"===e?1:"frosted"===e?2:0}function Z(e){const n=F("loading"),V=F(0),$=F(""),Z=F(0),ee=F(""),ne=F(""),te=F(0),re=F(""),ae=F(""),ie=F(0),oe=F("");let le=null,ue=null,se=null,ce=null,de=null,fe=null,pe=1,me=1,ve=!1,he=t.exposure,ge=null,xe=null,we=1,ye=1,Se=t.exposure,Te=0,Me=null,be=0,De=0,Pe=null,Ee=null,Re=null,We=null,ke=1,Ae=1,Le=null,Fe=null,Ce=0,Ue=0,ze="",He=0,Ve=0,Be=0,qe=Number.NEGATIVE_INFINITY,Ie=.5*window.innerWidth,Oe=.5*window.innerHeight,Ke=.5,Qe=.5,$e=.5,Ge=.5,Ye=null,_e=0,Xe=!1,Ne="",je=0,Je=null,Ze=null,en=!1,nn=null,tn=!1,rn=!1,an=!1,on=!1,ln=!1,un=0,sn=window.scrollX,cn=window.scrollY,dn=null,fn=null,pn=null,mn=[],vn=[],hn=[],gn=[],xn=[],wn=[],yn=!0,Sn=null,Tn=null,Mn=null,bn=0,Dn=null,Pn=0;const En=new Set;let Rn=!0,Wn=null,kn={x:0,y:-1},An=!1,Ln=null,Fn=0;const Cn=e.surfaceSpace??"fixed",Un=()=>"scroll"===Cn||"fixed"===Cn&&"frosted"===C(e.appearance),zn=e.wallpaperSourceCache??z();function Hn(){ue&&(ue.uniforms.uHasWallpaperTexture.value=!ve||"scroll"===Cn&&tn?0:1)}function Vn(){null!==nn&&(window.clearTimeout(nn),nn=null)}function Bn(e=performance.now()){Vn(),"scroll"===Cn&&tn&&(tn=!1,Hn(),lt(e,!1),document.documentElement.removeAttribute("data-glass-scroll-presentation"))}function qn(){"scroll"===Cn&&ue&&(Vn(),nn=window.setTimeout((()=>Bn()),180),tn||(tn=!0,Hn(),document.documentElement.dataset.glassScrollPresentation="native",lt(performance.now(),!1)))}function In(e){return!(e instanceof Element&&e!==document.documentElement&&e!==document.body)||mn.some((n=>e.contains(n)))}function On(e){if(e instanceof WheelEvent&&0===e.deltaX&&0===e.deltaY)return;if(e instanceof KeyboardEvent){const n=e.target;if(n instanceof HTMLElement&&(n.isContentEditable||["INPUT","SELECT","TEXTAREA"].includes(n.tagName)))return;if(!["ArrowDown","ArrowUp","End","Home","PageDown","PageUp"," "].includes(e.key))return}const n=function(e){const n=document.scrollingElement??document.documentElement,t=e.target;if(!(t instanceof Element))return n;if(t.closest(".v-overlay"))return null;const r=e instanceof WheelEvent?e:null;for(let a=t;a&&a!==document.body;a=a.parentElement){const e=getComputedStyle(a),n=/(auto|overlay|scroll)/.test(e.overflowY)&&a.scrollHeight>a.clientHeight&&(!r||r.deltaY<0&&a.scrollTop>0||r.deltaY>0&&a.scrollTop+a.clientHeight<a.scrollHeight);if(/(auto|overlay|scroll)/.test(e.overflowX)&&a.scrollWidth>a.clientWidth&&(!r||r.deltaX<0&&a.scrollLeft>0||r.deltaX>0&&a.scrollLeft+a.clientWidth<a.scrollWidth)||n)return a}return n}(e);n&&In(n)&&qn()}function Kn(t){!1!==e.syncDocumentState?H(n,t):n.value=t}function Qn(){if("fixed"===Cn)return{height:window.innerHeight,width:window.innerWidth};const n=e.canvas.value?.parentElement;return{height:Math.max(window.innerHeight,n?.scrollHeight??0,document.documentElement.scrollHeight),width:Math.max(window.innerWidth,n?.scrollWidth??0,document.documentElement.scrollWidth)}}function $n(){const e=ue?.uniforms.uPresentationSize.value;return e?{height:e.y,width:e.x}:{height:window.innerHeight,width:window.innerWidth}}function Gn(e,n){return"fixed"===Cn?{x:e,y:n}:{x:e+window.scrollX,y:n+window.scrollY}}function Yn(e){const n=e.getBoundingClientRect(),t="scroll"===Cn?window.scrollX:0,r="scroll"===Cn?window.scrollY:0;return{height:n.height,radii:[...X(e)],rank:0,width:n.width,x:n.left+t,y:n.top+r}}function _n(n=!0){if(n&&fn?.disconnect(),"scroll"===Cn){const n=e.canvas.value?.parentElement;n&&fn?.observe(n)}for(const e of mn)fn?.observe(e)}function Xn(){null!==Ee&&(cancelAnimationFrame(Ee),Ee=null)}function Nn(){null!==Ze&&cancelAnimationFrame(Ze),Ze=null,en=!1,rn=!1,an=!1,on=!1,ln=!1,un=0,Vn()}function jn(){null!==Re&&(cancelAnimationFrame(Re),Re=null)}function Jn(){null!==Dn&&cancelAnimationFrame(Dn),Dn=null,Pn=0,En.clear()}function Zn(){null!==We&&(window.clearTimeout(We),We=null)}function et(e,n){e?.dispose(),n?.dispose()}function nt(){ue&&de&&(ge&&ge!==de&&et(ge,xe),ge=null,xe=null,we=pe,ye=me,Se=he,ue.uniforms.uPreviousTexture.value=de,ue.uniforms.uPreviousFrostedTexture.value=fe?.texture??de,ue.uniforms.uPreviousCoverScale.value.copy(ue.uniforms.uCoverScale.value),ue.uniforms.uPreviousWallpaperExposure.value=he,ue.uniforms.uTextureMix.value=1,Te=0,Me=null,jn())}function tt(e){Re=null,"hidden"!==document.visibilityState&&(lt(e),ge&&null===Re&&(Re=requestAnimationFrame(tt)))}function rt(){null===Re&&ge&&"hidden"!==document.visibilityState&&(Re=requestAnimationFrame(tt))}async function at(e,n,t,r){if(!ue||!le)return null;const a=ue,i=function(){if(ce)return ce;if(!ue||!le)return null;const e={uDirection:{value:new le.Vector2(1,0)},uTexture:{value:null},uTextureSize:{value:new le.Vector2(1,1)}},n=new le.ShaderMaterial({depthTest:!1,depthWrite:!1,fragmentShader:"\nprecision highp float;\n\nuniform sampler2D uTexture;\nuniform vec2 uDirection;\nuniform vec2 uTextureSize;\nvarying vec2 vUv;\n\nvoid main() {\n  vec2 texel = uDirection / max(uTextureSize, vec2(1.0));\n  vec3 color =\n    texture2D(uTexture, vUv).rgb * 0.227027 +\n    texture2D(uTexture, vUv + texel * 1.384615).rgb * 0.316216 +\n    texture2D(uTexture, vUv - texel * 1.384615).rgb * 0.316216 +\n    texture2D(uTexture, vUv + texel * 3.230769).rgb * 0.070270 +\n    texture2D(uTexture, vUv - texel * 3.230769).rgb * 0.070270;\n  gl_FragColor = vec4(color, 1.0);\n}\n",uniforms:e,vertexShader:Q}),t=new le.Scene,r=new le.Mesh(ue.geometry,n);return r.frustumCulled=!1,t.add(r),ce={material:n,mesh:r,scene:t,uniforms:e},ce}();if(!i)return null;const o=Math.min(1,r/Math.max(n,t)),l=Math.max(1,Math.round(n*o)),u=Math.max(1,Math.round(t*o)),s=(e=!1)=>new le.WebGLRenderTarget(l,u,{depthBuffer:!1,generateMipmaps:e,magFilter:le.LinearFilter,minFilter:e?le.LinearMipmapLinearFilter:le.LinearFilter,stencilBuffer:!1}),c=s(),d=s(!0),f=a.renderer.getRenderTarget();try{return a.renderer.initTexture(e),await a.renderer.compileAsync(i.scene,a.camera),ue!==a?(d.dispose(),null):(i.uniforms.uDirection.value.set(1,0),i.uniforms.uTexture.value=e,i.uniforms.uTextureSize.value.set(n,t),a.renderer.setRenderTarget(c),a.renderer.render(i.scene,a.camera),i.uniforms.uDirection.value.set(0,1),i.uniforms.uTexture.value=c.texture,i.uniforms.uTextureSize.value.set(n,t),a.renderer.setRenderTarget(d),a.renderer.render(i.scene,a.camera),d)}catch(p){throw d.dispose(),p}finally{ue===a&&a.renderer.setRenderTarget(f),c.dispose()}}function it(){se&&(se.material.dispose(),se.readTarget.dispose(),se.writeTarget.dispose(),se=null,ue&&(ue.uniforms.uFlowTexture.value=null,ue.uniforms.uHasFlowTexture.value=0))}function ot(){if(!ue||!le)return;if(!Pt().flowField)return void it();if(se)return;const e=()=>new le.WebGLRenderTarget(1,1,{depthBuffer:!1,magFilter:le.LinearFilter,minFilter:le.LinearFilter,stencilBuffer:!1}),n={uDecay:{value:1},uInjection:{value:0},uPointer:{value:ue.uniforms.uPointer.value},uPrevious:{value:null},uTexelSize:{value:new le.Vector2(1,1)},uVelocity:{value:ue.uniforms.uPointerVelocity.value},uViewportAspect:{value:window.innerWidth/Math.max(window.innerHeight,1)}},t=new le.ShaderMaterial({depthTest:!1,depthWrite:!1,fragmentShader:G,uniforms:n,vertexShader:Q}),r=new le.Scene,a=new le.Mesh(ue.geometry,t);a.frustumCulled=!1,r.add(a),se={material:t,mesh:a,readTarget:e(),scene:r,uniforms:n,writeTarget:e()},ue.uniforms.uHasFlowTexture.value=1}function lt(n=performance.now(),t=!0){if(ue&&C(e.active)&&"hidden"!==document.visibilityState){if(function(n){if(!ue||!ge)return!1;const t=C(e.transitionDuration??0),r=T(n-Te,t);ue.uniforms.uTextureMix.value=r,r>=1&&nt()}(n),se&&t){ue.renderer.setScissorTest(!1),se.uniforms.uPrevious.value=se.readTarget.texture,ue.renderer.setRenderTarget(se.writeTarget),ue.renderer.render(se.scene,ue.camera),ue.renderer.setRenderTarget(null);const e=se.readTarget;se.readTarget=se.writeTarget,se.writeTarget=e,ue.uniforms.uFlowTexture.value=se.readTarget.texture}if("scroll"===Cn){const{height:e}=$n(),n=ke/Math.max(e,1),t=Math.max(0,Math.floor((e-window.scrollY-window.innerHeight)*n)),r=Math.min(ke-t,Math.ceil(window.innerHeight*n)+2);ue.renderer.setScissorTest(!0),ue.renderer.setScissor(0,t,Ae,r),ue.renderer.clear()}else ue.renderer.setScissorTest(!1);ue.renderer.render(ue.scene,ue.camera),V.value+=1}}function ut(e){Ee=null,lt(e)}function st(){null===Ee&&ue&&(Ee=requestAnimationFrame(ut))}function ct(n=performance.now()){if(!ue)return;Mn&&n-bn>=96&&(Mn=null,gn=gn.filter((e=>"outgoing"!==e.role)).map((e=>({...e,role:e.key===Sn?"active":"stable"}))));const t=$n(),r=xn.map((e=>E(e.rect,t.width,t.height))),a=ue.uniforms.uInteractionRects.value,i=ue.uniforms.uInteractionRadii.value;for(let e=0;e<8;e+=1){const n=r[e],t=n?.rect??[0,0,0,0],o=n?.radii??[0,0,0,0];a[e].set(t[0],t[1],t[2],t[3]),i[e].set(o[0],o[1],o[2],o[3])}ue.uniforms.uInteractionRectCount.value=r.length;const o=gn.map((e=>E(e.rect,t.width,t.height))),l=ue.uniforms.uRects.value,u=ue.uniforms.uRadii.value,s=ue.uniforms.uSurfaceWeights.value,c=ue.uniforms.uSurfaceDynamics.value,d=Mn?R(n-bn,96):{incoming:1,outgoing:0},f="scroll"===Cn&&"frosted"!==C(e.appearance)?Math.min(1,Math.max(0,C(e.pageMotion?.opacity??1))):1,p=Rn?f:0;for(let e=0;e<8;e+=1){const n=o[e],t=gn[e],r=n?.rect??[0,0,0,0],a=n?.radii??[0,0,0,0];l[e].set(r[0],r[1],r[2],r[3]),u[e].set(a[0],a[1],a[2],a[3]);const i="outgoing"===t?.role?d.outgoing:"active"===t?.role?d.incoming:t?1:0;s[e]=i*p,c[e]="static-material"===t?.mode?0:1}ue.uniforms.uRectCount.value=o.length}function dt(e){return e.width>=24&&e.height>=24}function ft(){const e=new Set(gn.map((e=>e.key))),n="scroll"===Cn?window.scrollX:0,t="scroll"===Cn?window.scrollY:0,r=Gn(Ie,Oe),a=wn.filter((n=>e.has(n.owner))).map((e=>{const{rect:a}=e,i=Math.min(n+window.innerWidth,a.x+a.width)-Math.max(n,a.x),o=Math.min(t+window.innerHeight,a.y+a.height)-Math.max(t,a.y),l=a.x+a.width>=n-96&&a.x<=n+window.innerWidth+96&&a.y+a.height>=t-96&&a.y<=t+window.innerHeight+96;return{candidate:e,distance:Math.hypot(a.x+.5*a.width-r.x,a.y+.5*a.height-r.y),visible:i>=24&&o>=24,inOverscan:l}})).filter((e=>dt(e.candidate.rect)&&(e.candidate.key===Tn||e.inOverscan))).sort(((e,n)=>{const t=e.candidate.key===Tn;return t!==(n.candidate.key===Tn)?t?-1:1:e.visible!==n.visible?e.visible?-1:1:e.distance-n.distance})).map((e=>e.candidate)),i=window.innerWidth<=600?D:P;xn=a.slice(0,i)}function pt(e){const n=window.innerWidth;hn=function(e,n,t,r){const a="scroll"===r?window.scrollX:0,i="scroll"===r?window.scrollY:0;return e.filter((({rect:e})=>{const r=Math.min(a+n,e.x+e.width)-Math.max(a,e.x),o=Math.min(i+t,e.y+e.height)-Math.max(i,e.y);return r>=24&&o>=24}))}(vn,n,window.innerHeight,Cn);const t=new Set(hn.map((e=>e.key)));Sn&&!t.has(Sn)&&(Sn=null,Tn=null),Mn&&!t.has(Mn)&&(Mn=null);gn=M(gn,hn,n<=600?D:P,Sn??void 0,Mn??void 0),ft(),ct(e)}function mt(n=performance.now(),t=!0){if(!ue)return;const r=window.innerWidth,a=[];vn=function(e,n,t,r="all",a=!1,i){const o=[],l=new Set;for(const{rank:s,selector:c,space:d}of B){const u=O(c,d);if(!("all"!==r&&u!==r||e<=600&&"clear"===t&&".layout-navbar"===c))for(const t of document.querySelectorAll(c)){if(l.has(t))continue;if(l.add(t),t.closest(".v-overlay"))continue;i?.push(t);const r=t.getBoundingClientRect();if(!N(t,r))continue;const c=Math.max(0,r.left),d=Math.max(0,r.top),f=Math.min(e,r.right),p=Math.min(n,r.bottom),m=Math.max(0,p-d),v=Math.max(0,f-c);if(!a&&(v<24||m<24))continue;const h="scroll"===u?window.scrollX:0,g="scroll"===u?window.scrollY:0;o.push({key:t,mode:j(t),rect:{height:r.height,radii:[...X(t)],rank:s+.001*o.length,width:r.width,x:r.left+h,y:r.top+g},visibleArea:v*m})}}const u=[];for(const s of o.sort(((e,n)=>{if(e.key!==n.key){if(e.key.contains(n.key))return-1;if(n.key.contains(e.key))return 1}return e.rect.rank-n.rect.rank||e.visibleArea-n.visibleArea}))){const{rect:e}=s;u.some((n=>n.mode===s.mode&&e.x>=n.rect.x&&e.y>=n.rect.y&&e.x+e.width<=n.rect.x+n.rect.width&&e.y+e.height<=n.rect.y+n.rect.height))||u.push({key:s.key,mode:s.mode,rect:e})}return u}(r,window.innerHeight,C(e.appearance),Cn,!0,a),yn?function(){const e=new Set,n=[],t=(t,r,a,i)=>{if(e.has(t)||!t.isConnected||j(t)!==a)return;const o=i??Yn(t);e.add(t),n.push({key:t,mode:a,owner:r,rect:o})};for(const r of vn){const e=r.mode??"dynamic";if("static-material"===e)continue;const n=r.key.matches(I);n&&t(r.key,r.key,e,r.rect);const a=[...r.key.querySelectorAll(I)];a.length>0?a.forEach((n=>t(n,r.key,e))):n||t(r.key,r.key,e,r.rect)}wn=n,yn=!1}():function(){const e=new Map(vn.map((e=>[e.key,e])));wn=wn.flatMap((n=>{if(!n.key.isConnected||!n.owner.isConnected||j(n.key)!==n.mode||!e.has(n.owner))return[];const t=e.get(n.key)?.rect??Yn(n.key);return[{...n,rect:t}]}))}(),pt(n);(a.length!==mn.length||a.some(((e,n)=>e!==mn[n])))&&(mn=a,_n()),t&&st()}function vt(e){if("scroll"!==Cn||null===Ze||!ue)return!1;if(ln||=e,un=0,!rn)return an=!0,!0;if(on)return!0;on=!0,an=!1;const n=performance.now();return mt(n,!1),lt(n,!1),!0}function ht(){vt(!1)||null===Le&&ue&&(Le=requestAnimationFrame((e=>{Le=null,mt(e,!1),lt(e,!1)})))}function gt(n){if(void 0!==n&&(Wn=n),vt(!0))return;if(Ce=0,Ue=0,ze="",null!==Fe||!ue)return;const t=n=>{if(Fe=null,!ue||!C(e.active)||"hidden"===document.visibilityState)return;mt(n,!1);const r=gn.map((e=>{const{height:n,width:t,x:r,y:a}=e.rect;return`${r.toFixed(2)},${a.toFixed(2)},${t.toFixed(2)},${n.toFixed(2)}`})).join("|");if(Ue=r===ze?Ue+1:0,ze=r,Ce+=1,lt(n,!1),Ue<2&&Ce<6)Fe=requestAnimationFrame(t);else if(!Rn){Rn=!0,ct(n),lt(n,!1);const t=Wn;Wn=null,null!==t&&e.pageMotion?.acknowledgeGeometryReady(t,n)}};Fe=requestAnimationFrame(t)}function xt(){null!==Je&&window.clearTimeout(Je),Ne="",je=0;const e=()=>{if(Je=null,!ue)return;const n=Qn(),t=`${window.innerWidth},${window.innerHeight},${n.width},${n.height}`;if(je=t===Ne?je+1:1,Ne=t,je>=2)return Ct(),Ne="",void(je=0);Je=window.setTimeout(e,80)};Je=window.setTimeout(e,80)}function wt(n=performance.now()){return!(!ue||"scroll"!==Cn||!C(e.pageMotion?.active??!1))&&(null!==Je&&window.clearTimeout(Je),Je=null,Ne="",je=0,Ct(),mt(n,!1),lt(n,!1),!0)}function yt(n){if(!ue)return;const t="scroll"===Cn?e.canvas.value?.parentElement:null,r=t&&n.some((e=>e.target===t));if(r&&wt())return;if(r&&xt(),!n.some((e=>e.target!==t)))return;if(vt(!1))return;const a=performance.now();mt(a,!1),lt(a,!1)}function St(){vt(!1)||null===Dn&&ue&&(Dn=requestAnimationFrame((n=>{Dn=null,ue&&C(e.active)&&"hidden"!==document.visibilityState?(mt(n,!1),lt(n,!1),En.size>0&&n<Pn?St():(En.clear(),gt())):Jn()})))}function Tt(e){if(!(e instanceof HTMLElement))return null;const n=e.matches(q)?e:e.closest(q);return n&&B.some((({selector:e,space:t})=>n.matches(e)&&O(e,t)===Cn))?n:null}function Mt(e){if("transform"!==e.propertyName)return;const n=Tt(e.target);n&&(En.add(n),Pn=performance.now()+1e3,St())}function bt(e){if("transform"!==e.propertyName)return;const n=Tt(e.target);n&&(En.delete(n),0===En.size&&gt())}function Dt(e=window.innerWidth,n=window.innerHeight){if(!ue)return;const t=S(e,n,me,pe),r=S(e,n,ye,we);ue.uniforms.uCoverScale.value.set(t.x,t.y),ue.uniforms.uPreviousCoverScale.value.set(r.x,r.y)}function Pt(n=C(e.routeKey)){return a(C(e.quality),n)}function Et(n){return Y(C(e.appearance),C(e.quality),C(e.routeKey),n)}function Rt(){Pe&&et(Pe.texture,Pe.frostedTarget),Pe=null,ne.value="",te.value=0,re.value=""}function Wt(){ae.value="",ie.value=0,oe.value=""}function kt(){De+=1,Rt(),Wt()}function At(){const n=C(e.pendingWallpaperUrl??""),t=C(e.pendingWallpaperRevision??0);n&&t>0&&vr(n,t)}function Lt(){return C(e.motionStrength??r)}function Ft(){return m(C(e.flowStrength??Lt()))}function Ct(){if(!ue)return;const e=window.innerWidth,n=window.innerHeight,t=Qn(),r=Pt(),a="scroll"===Cn?h(t.width,t.height,r.bufferQuality,window.devicePixelRatio):g(e,n,e<=600,r.bufferQuality,window.devicePixelRatio),i=Ae!==a.width||ke!==a.height,o=ue.uniforms.uPresentationSize.value.x!==t.width||ue.uniforms.uPresentationSize.value.y!==t.height;if(ke=a.height,Ae=a.width,i&&ue.renderer.setSize(a.width,a.height,!1),ue.uniforms.uVisibleViewportSize.value.set(e,n),ue.uniforms.uPresentationSize.value.set(t.width,t.height),ue.uniforms.uScrollOffset.value.set("scroll"===Cn?window.scrollX:0,"scroll"===Cn?window.scrollY:0),se){const t=Math.max(96,Math.round(.25*a.width)),r=Math.max(96,Math.round(.25*a.height));(se.readTarget.width!==t||se.readTarget.height!==r)&&(se.readTarget.setSize(t,r),se.writeTarget.setSize(t,r)),se.uniforms.uTexelSize.value.set(1/t,1/r),se.uniforms.uViewportAspect.value=e/Math.max(n,1)}Dt(e,n),mt(performance.now(),!1),i||o?lt(performance.now(),!1):ht()}function Ut(n,t){const r=C(e.wallpaperUrl),a=e=>"auto"===e.textureSource?i(r,window.location.href)?"wallpaper":"procedural":e.textureSource;return n.textureLimit!==t.textureLimit||a(n)!==a(t)}function zt(e,n,t){return n>=e.x&&n<=e.x+e.width&&t>=e.y&&t<=e.y+e.height}function Ht(e,n){0===hn.length&&mt();const t=hn.find((t=>zt(t.rect,e,n)));if(!t)return null;const r=wn.filter((r=>r.owner===t.key&&dt(r.rect)&&zt(r.rect,e,n))).sort(((e,n)=>e.rect.width*e.rect.height-n.rect.width*n.rect.height));return{clip:r[0]?.key??t.key,surface:t}}function Vt(e,n,t){if(Sn===e)return!1;const r=gn.some((n=>n.key===e));Mn=t||r?null:Sn,Sn=e,bn=n;const a=window.innerWidth<=600?D:P;return gn=M(gn,hn,a,Sn,Mn??void 0),ft(),ct(n),!0}function Bt(e,n){Ke=e,Qe=n,$e=e,Ge=n,ue?.uniforms.uPointer.value.set(e,n)}function qt(e,n,t,r,a){if(!ue)return;const i=$n(),o=e/Math.max(i.width,1),l=1-n/Math.max(i.height,1),u=Math.hypot(o-r,l-a);if(t-qe<36&&u<.012)return;const s=ue.uniforms.uTrail.value,c=Math.min(Pt().trailCount,Math.max(1,Math.ceil(u/.045)));if(c>1){for(let e=0;e<s.length;e+=1){if(e>=c){s[e].z=0;continue}const n=e/(c-1);s[e].set(o+(r-o)*n,l+(a-l)*n,1-.28*n,0)}qe=t}else{for(let e=s.length-1;e>0;e-=1)s[e].copy(s[e-1]),s[e].z*=.74;s[0].set(o,l,1,0),qe=t}}function It(){if(_e=0,Ve=0,qe=Number.NEGATIVE_INFINITY,Tn=null,xn=[],ue){Bt(Ke,Qe),ue.uniforms.uInteractionRectCount.value=0,ue.uniforms.uMotion.value=0,ue.uniforms.uPointerVelocity.value.set(0,0);for(const e of ue.uniforms.uTrail.value)e.z=0;se&&(se.uniforms.uDecay.value=0,se.uniforms.uInjection.value=0)}}function Ot(n){if(!ue||!C(e.active)||"hidden"===document.visibilityState)return Ee=null,void(Xe=!1);const t=Pt(),r=Math.max(0,n-He),a=Ft(),i=Math.max(.35,.55+.45*a),o=t.motionDuration*i,l=t.motionHalfLife*i,u=W(r,o,l);if(ct(n),u<=0)return It(),lt(),void(Xe=!1);const s=Ve>0?Math.min(64,Math.max(0,n-Ve)):16.67;Ve=n,ue.uniforms.uMotion.value=u,se&&(se.uniforms.uDecay.value=k(t.flowHalfLife,s),se.uniforms.uInjection.value=_e),_e=0,lt(),se&&(se.uniforms.uInjection.value=0),Ee=requestAnimationFrame(Ot)}function Kt(e,n,t,r){const a=Math.max(window.innerWidth,1),i=Math.max(window.innerHeight,1),o=$n(),l=Gn(e,n),u=Gn(Ie,Oe),s=Math.max(8,t-Be),c=u.x/Math.max(o.width,1),d=1-u.y/Math.max(o.height,1),f=(e-Ie)/a*Math.min(2,16.67/s),p=-(n-Oe)/i*Math.min(2,16.67/s),m=Math.hypot(f,p),v=m>.09?.09/m:1,h=Ht(l.x,l.y);if(Ie=e,Oe=n,Be=t,!ue||!h||"static-material"===h.surface.mode)return;const g=matchMedia("(prefers-reduced-motion: reduce)").matches,x=Tn!==h.clip;Tn=h.clip;const w=Vt(h.surface.key,t,g);x&&!w&&(ft(),ct(t));const y=!Xe,S=Number.isFinite(qe),T=l.x/Math.max(o.width,1),M=1-l.y/Math.max(o.height,1);if(y&&!S)Bt(T,M),qt(l.x,l.y,t,T,M);else{qt(l.x,l.y,t,c,d);const e=Pt();!function(e,n,t){if(!ue)return;Ke=e,Qe=n;const r=Math.min(1,Math.max(0,t));$e+=(Ke-$e)*r,Ge+=(Qe-Ge)*r,ue.uniforms.uPointer.value.set($e,Ge)}(T,M,window.innerWidth<=600||matchMedia("(pointer: coarse)").matches||null!==Ye?1:e.pointerImmediateResponse)}const D={x:f*v,y:p*v};if(kn=b(kn,D,Math.hypot(D.x,D.y),y),ue.uniforms.uPointerVelocity.value.set(D.x,D.y),ue.uniforms.uWakeDirection.value.set(kn.x,kn.y),ue.uniforms.uTrailCount.value=Pt().trailCount,He=t,g)return It(),void st();if(ue.uniforms.uMotion.value=1,Ft()<=0){Xe=!1,Xn(),_e=0;for(const e of ue.uniforms.uTrail.value)e.z=0;return se&&(se.uniforms.uDecay.value=0,se.uniforms.uInjection.value=0),void st()}_e=Math.max(_e,Math.min(1,18*m)),Xe||(Xn(),Xe=!0,Ve=0,Ee=requestAnimationFrame(Ot))}function Qt(e){"touch"!==e.pointerType&&Kt(e.clientX,e.clientY,e.timeStamp||performance.now())}function $t(e,n){for(let t=0;t<e.length;t+=1){const r=e.item(t);if(r&&(null===n||r.identifier===n))return r}return null}function Gt(e){if(null!==Ye)return;const n=$t(e.changedTouches,null);if(!n)return;const t=e.timeStamp||performance.now();Ye=n.identifier,Ie=n.clientX,Oe=n.clientY,Be=t;const r=Gn(n.clientX,n.clientY),a=$n(),i=Ht(r.x,r.y);ue&&"dynamic"===i?.surface.mode&&(Tn=i.clip,Vt(i.surface.key,t,matchMedia("(prefers-reduced-motion: reduce)").matches),Bt(r.x/Math.max(a.width,1),1-r.y/Math.max(a.height,1)),qt(r.x,r.y,t,r.x/Math.max(a.width,1),1-r.y/Math.max(a.height,1)),st())}function Yt(e){const n=$t(e.touches,Ye);if(!n)return;const t=e.timeStamp||performance.now();Kt(n.clientX,n.clientY,t)}function _t(e){$t(e.changedTouches,Ye)&&(Ye=null)}function Xt(e){"pointermove"!==e.type?"touchstart"!==e.type?"touchmove"!==e.type?_t(e):Yt(e):Gt(e):Qt(e)}function Nt(n){if(Ze=null,rn=!1,on=!1,"scroll"!==Cn||!ue||!C(e.active)||"hidden"===document.visibilityState)return en=!1,void(un=0);const t=en;en=!1;const r=window.scrollX,a=window.scrollY,i=r!==sn||a!==cn;sn=r,cn=a,ue.uniforms.uScrollOffset.value.set(r,a),an?(an=!1,mt(n,!1)):(t||i)&&pt(n),un=t||i?0:un+1,Xe||lt(n,!1),rn=!0,En.size>0&&(n<Pn?(an=!0,un=0):(En.clear(),ln=!0)),un<2?Ze=requestAnimationFrame(Nt):(Bn(n),ln&&(ln=!1,gt()))}function jt(){null===Ze&&"scroll"===Cn&&ue&&(Ze=requestAnimationFrame(Nt))}function Jt(e){if("scroll"!==Cn||!ue)return;const n=e.target;if(!In(n))return;qn(),rn=!1,on=!1;if(!(n instanceof Element)||n===document.documentElement||n===document.body)ue.uniforms.uScrollOffset.value.set(window.scrollX,window.scrollY);else{if(!(n instanceof Element&&mn.some((e=>n.contains(e)))))return;an=!0}en=!0,jt(),null!==Le&&(cancelAnimationFrame(Le),Le=null,vt(!1)),null!==Fe&&(cancelAnimationFrame(Fe),Fe=null,vt(!0)),null!==Dn&&(cancelAnimationFrame(Dn),Dn=null,vt(!1))}function Zt(e){if("scroll"!==Cn||!ue)return;const n=e.target;n instanceof Element&&n!==document.documentElement&&n!==document.body&&mn.some((e=>n.contains(e)))&&(an=!0),en=!1,un=0,jt()}function er(){Xn(),Nn(),Bn(),jn(),Jn(),Xe=!1}function nr(){if(Ln)return Ln;const n=Fn,t=()=>C(e.active)&&"hidden"!==document.visibilityState,r=(async()=>{Zn(),t()&&(await A(),n===Fn&&t()&&(ue?(Ct(),mt(),It(),lt(performance.now()),rt()):await xr()))})();return Ln=r,r.finally((()=>{Ln===r&&(Ln=null)})),r}function tr(e){Zn(),We=window.setTimeout((()=>{We=null,e()&&cr(!1)}),u)}function rr(){if("hidden"===document.visibilityState)return er(),void tr((()=>"hidden"===document.visibilityState));nr()}function ar(){"visible"===document.visibilityState&&(er(),tr((()=>"visible"===document.visibilityState&&!document.hasFocus())))}function ir(){"visible"===document.visibilityState&&nr()}function or(n){n.preventDefault();const t=e.canvas.value;cr(!1),An=!0,t?.addEventListener("webglcontextrestored",lr,{once:!0}),Kn("fallback")}function lr(){An&&(An=!1,xr(!1))}function ur(){"scroll"===Cn?xt():Ct()}function sr(){fn=new ResizeObserver(yt),_n(!1);const e=new Set;function n(n,t){n&&!e.has(n)&&(e.add(n),pn?.observe(n,{attributeFilter:["data-glass-optical-mode"],attributes:!0,childList:!0,subtree:t}))}pn=new MutationObserver((e=>{n(document.querySelector(".v-overlay-container"),!0),function(e){return e.some((e=>"attributes"===e.type||[...e.addedNodes,...e.removedNodes].some(K)))}(e)&&(yn=!0,wt(),gt())})),n(document.querySelector(".app-wrapper"),!0),n(document.querySelector(".v-overlay-container"),!0),n(document.body,!1),pn.observe(document.documentElement,{attributeFilter:["data-theme-radius"],attributes:!0})}function cr(n=!0){Fn+=1,be+=1,De+=1,An=!1,Xe=!1,Xn(),Nn(),jn(),Jn(),Zn(),null!==Le&&(cancelAnimationFrame(Le),Le=null),null!==Fe&&(cancelAnimationFrame(Fe),Fe=null),null!==Je&&(window.clearTimeout(Je),Je=null),Ne="",je=0,dn?.(),dn=null,e.interactionSource||(window.removeEventListener("pointermove",Qt),window.removeEventListener("touchstart",Gt),window.removeEventListener("touchmove",Yt),window.removeEventListener("touchend",_t),window.removeEventListener("touchcancel",_t)),window.removeEventListener("resize",ur),window.removeEventListener("transitionrun",Mt,!0),window.removeEventListener("transitionend",bt,!0),window.removeEventListener("transitioncancel",bt,!0),"scroll"===Cn&&(window.removeEventListener("wheel",On,!0),window.removeEventListener("touchmove",On,!0),window.removeEventListener("keydown",On,!0),window.removeEventListener("scroll",Jt,!0),window.removeEventListener("scrollend",Zt)),e.canvas.value?.removeEventListener("webglcontextlost",or),e.canvas.value?.removeEventListener("webglcontextrestored",lr),fn?.disconnect(),fn=null,pn?.disconnect(),pn=null,mn=[],vn=[],hn=[],gn=[],xn=[],wn=[],yn=!0,Sn=null,Tn=null,Mn=null,bn=0,kn={x:0,y:-1},document.documentElement.removeAttribute("data-glass-wallpaper-loading"),Ye=null,"scroll"===Cn&&(tn=!1,document.documentElement.removeAttribute("data-glass-scroll-presentation")),Ie=.5*window.innerWidth,Oe=.5*window.innerHeight,Ke=.5,Qe=.5,$e=.5,Ge=.5,_e=0,Ve=0,ge&&ge!==de&&et(ge,xe),ge=null,xe=null,we=1,ye=1,Se=t.exposure,Te=0,Me=null,et(de,fe),de=null,fe=null,pe=1,me=1,ve=!1,he=t.exposure,$.value="",Z.value=0,ee.value="",Rt(),Wt(),it(),ce&&(ce.material.dispose(),ce=null),ue&&(ue.geometry.dispose(),ue.material.dispose(),ue.renderer.dispose(),n&&ue.renderer.forceContextLoss(),ue=null),delete document.documentElement.dataset.glassRendererState}function dr(e,n,t){e===be&&(cr(),Kn("fallback"))}async function fr(n,t){const r=++be,a=Boolean(ue&&de);a||Kn("loading"),document.documentElement.setAttribute("data-glass-wallpaper-loading","true");try{await hr(C(e.wallpaperUrl),r,t)}catch(i){if(r!==be)return;if(a&&ue&&de)return Kn("ready"),void st();dr(r)}finally{r===be&&document.documentElement.removeAttribute("data-glass-wallpaper-loading")}}function pr(n,t,r,a,i,o,l=C(e.transitionStartedAt??0),u=!1){if(!ue)return void et(n,t);const s=Boolean(de)&&l>0&&(u||Boolean(C(e.previousWallpaperUrl??"")));jn(),s&&de?(ge&&ge!==de&&et(ge,xe),ge=de,xe=fe,we=pe,ye=me,Se=he,de=n,fe=t,pe=a,me=r,he=o.exposure,ue.uniforms.uPreviousTexture.value=ge,ue.uniforms.uPreviousFrostedTexture.value=xe?.texture??ge,ue.uniforms.uTexture.value=de,ue.uniforms.uFrostedTexture.value=fe?.texture??de,ue.uniforms.uPreviousWallpaperExposure.value=Se,ue.uniforms.uWallpaperExposure.value=he,Te=l,ue.uniforms.uTextureMix.value=u?0:T(performance.now()-Te,C(e.transitionDuration??0)),Dt(),rt()):(ge&&ge!==de&&et(ge,xe),et(de,fe),ge=null,xe=null,de=n,fe=t,pe=a,me=r,he=o.exposure,we=a,ye=r,Se=o.exposure,ue.uniforms.uPreviousTexture.value=n,ue.uniforms.uPreviousFrostedTexture.value=t?.texture??n,ue.uniforms.uTexture.value=n,ue.uniforms.uFrostedTexture.value=t?.texture??n,ue.uniforms.uPreviousWallpaperExposure.value=o.exposure,ue.uniforms.uWallpaperExposure.value=o.exposure,ue.uniforms.uTextureMix.value=1,Te=0,Me=null,Dt()),ve=i,Hn(),ue.uniforms.uHasFrostedTexture.value=i&&t?1:0}async function mr(n){if(!ue||!le||!n)return null;const r=C(e.appearance),o=C(e.quality),l=C(e.routeKey),u=a(o,l),s=Y(r,o,l,n);if("procedural"===u.textureSource||"auto"===u.textureSource&&!i(n,window.location.href)){const e=document.createElement("canvas");e.width=1,e.height=1;const n=new le.CanvasTexture(e);return n.colorSpace=le.SRGBColorSpace,n.generateMipmaps=!1,n.minFilter=le.LinearFilter,n.magFilter=le.LinearFilter,{frostedTarget:null,hasWallpaperTexture:!1,height:1,preparationKey:s,texture:n,toneProfile:{...t},width:1}}const{textureLimit:c}=u,d="frosted"===r,f="high"===o?2048:1536,p=`${f}:${n}`,m=await zn.get(p,(async()=>{const e=await x(n),t=e.corsReady?w(n):void 0;let r=null,a=t?.image;if(!a){const e=new le.TextureLoader;e.setCrossOrigin("anonymous"),r=await e.loadAsync(n),a=r.image}const i=a.naturalWidth||a.width,o=a.naturalHeight||a.height,l=Math.max(i,o),u=Math.min(l,c,f),s=Math.min(1,u/l),d=document.createElement("canvas");d.width=Math.max(1,Math.round(i*s)),d.height=Math.max(1,Math.round(o*s));const p=d.getContext("2d"),m=p?d:a;return p&&p.drawImage(a,0,0,d.width,d.height),r?.dispose(),{height:p?d.height:o,image:m,toneProfile:t?.profile??e.profile??y(a,i,o),width:p?d.width:i}})),v=new le.Texture(m.image);v.needsUpdate=!0;const h=m.width,g=m.height;v.colorSpace=le.SRGBColorSpace,v.generateMipmaps=!1,v.minFilter=le.LinearFilter,v.magFilter=le.LinearFilter;let S=null;try{d&&(S=await at(v,h,g,.125*Math.max(h,g)))}catch(T){}return{frostedTarget:S,hasWallpaperTexture:!0,height:g,preparationKey:s,texture:v,toneProfile:m.toneProfile,width:h}}async function vr(n,t){const r=++De;if(Rt(),Wt(),!n||!ue||An||n===C(e.wallpaperUrl))return;const a=Et(n);try{const e=await mr(n);if(!e)return;if(r!==De||!ue||An||a!==e.preparationKey||a!==Et(n))return void et(e.texture,e.frostedTarget);if(ue.renderer.initTexture(e.texture),await ue.renderer.compileAsync(ue.scene,ue.camera),r!==De||!ue||An||a!==Et(n))return void et(e.texture,e.frostedTarget);Pe=e,ne.value=n,te.value=t,re.value=a}catch(i){r===De&&(ae.value=n,ie.value=t,oe.value=a)}}async function hr(e,n,t){if(!ue||!le||!e)return;const r=await mr(e);if(!r)return;if(n!==be||!ue||An||r.preparationKey!==Et(e))return void et(r.texture,r.frostedTarget);if(await ue.renderer.compileAsync(ue.scene,ue.camera),n!==be||!ue||An||r.preparationKey!==Et(e))return void et(r.texture,r.frostedTarget);const a=performance.now();t?.(),pr(r.texture,r.frostedTarget,r.width,r.height,r.hasWallpaperTexture,r.toneProfile),mt(a,!1),It(),lt(a,!1),$.value=e,Z.value=0,ee.value=r.preparationKey,Kn("ready"),rt()}function gr(e,t,r){return Boolean(ue&&!An&&"ready"===n.value&&Pe&&ne.value===e&&te.value===t&&re.value===r&&r===Et(e))}async function xr(n=!0){if(cr(n),!C(e.active)||!e.canvas.value)return;if(!window.WebGLRenderingContext||yr.matches||!C(e.wallpaperUrl))return void Kn("fallback");Kn("loading");const a=++be;try{if(le=await o((()=>import("./three.module-CA6zAcOF.js")),[],import.meta.url),a!==be||!e.canvas.value)return;const n=le.Vector4,i=e.canvas.value,u=function(e){if("undefined"==typeof WebGL2RenderingContext)return null;const n=e.getContext("webgl2",{alpha:!0,antialias:!1,depth:!0,failIfMajorPerformanceCaveat:!1,powerPreference:"high-performance",premultipliedAlpha:!0,preserveDrawingBuffer:!1,stencil:!1});return!n||n.isContextLost()?null:(n.pixelStorei(n.UNPACK_FLIP_Y_WEBGL,!1),n.pixelStorei(n.UNPACK_PREMULTIPLY_ALPHA_WEBGL,!1),n)}(i),m=new le.WebGLRenderer({alpha:!0,antialias:!1,canvas:i,...u?{context:u}:{},powerPreference:"high-performance",premultipliedAlpha:!0});m.setClearColor(0,0),m.setPixelRatio(1);const h=new le.BufferGeometry;h.setAttribute("position",new le.Float32BufferAttribute([-1,-1,0,3,-1,0,-1,3,0],3));const g=s(C(e.appearance),C(e.transparencyStrength??r)),x={uAppearance:{value:J(C(e.appearance))},uBackgroundVisibility:{value:g.backgroundVisibility},uCoverScale:{value:new le.Vector2(1,1)},uDeformationStrength:{value:v(C(e.deformationStrength??Lt()))},uDynamicsOnly:{value:Un()?1:0},uFlowTexture:{value:null},uFlowStrength:{value:Ft()},uHasFlowTexture:{value:0},uHasFrostedTexture:{value:0},uHasWallpaperTexture:{value:0},uInteractionRadii:{value:Array.from({length:8},(()=>new n))},uInteractionRectCount:{value:0},uInteractionRects:{value:Array.from({length:8},(()=>new n))},uMotion:{value:0},uMotionExpansion:{value:p(C(e.flowStrength??Lt()))},uMaxRefractionPixels:{value:f(Pt().maxRefractionPixels,C(e.deformationStrength??Lt()))},uPointer:{value:new le.Vector2(.5,.5)},uPointerVelocity:{value:new le.Vector2(0,0)},uPresentationSize:{value:new le.Vector2(window.innerWidth,window.innerHeight)},uPreviousCoverScale:{value:new le.Vector2(1,1)},uPreviousWallpaperExposure:{value:t.exposure},uQuality:{value:"high"===C(e.quality)?1:0},uReflectionStrength:{value:d(C(e.reflectionStrength??r))},uRadii:{value:Array.from({length:8},(()=>new n))},uRectCount:{value:0},uRects:{value:Array.from({length:8},(()=>new n))},uSurfaceWeights:{value:Array.from({length:8},(()=>0))},uSurfaceDynamics:{value:Array.from({length:8},(()=>1))},uPreviousTexture:{value:null},uPreviousFrostedTexture:{value:null},uTexture:{value:null},uFrostedTexture:{value:null},uTextureMix:{value:1},uWallpaperExposure:{value:t.exposure},uTintColor:{value:new le.Color(C(e.tintColor))},uFrostDetailLevel:{value:g.frostDetailLevel},uSurfaceDensity:{value:g.surfaceDensity},uTintDensity:{value:g.tintDensity},uTransmissionStrength:{value:l(C(e.transmissionStrength??r))},uTranslationStrength:{value:c(C(e.translationStrength??Lt()))},uTrail:{value:Array.from({length:4},(()=>new n(.5,.5,0,0)))},uTrailCount:{value:Pt().trailCount},uVisibleViewportSize:{value:new le.Vector2(window.innerWidth,window.innerHeight)},uScrollOffset:{value:new le.Vector2(0,0)},uWakeDirection:{value:new le.Vector2(0,-1)}},w=new le.ShaderMaterial({depthTest:!1,depthWrite:!1,fragmentShader:_,transparent:!0,uniforms:x,vertexShader:Q}),y=new le.Scene,S=new le.OrthographicCamera(-1,1,1,-1,0,1),T=new le.Mesh(h,w);T.frustumCulled=!1,y.add(T),ue={camera:S,geometry:h,material:w,mesh:T,renderer:m,scene:y,uniforms:x},ot(),sr(),e.interactionSource?dn=e.interactionSource.subscribe(Cn,Xt):(window.addEventListener("pointermove",Qt,{passive:!0}),window.addEventListener("touchstart",Gt,{passive:!0}),window.addEventListener("touchmove",Yt,{passive:!0}),window.addEventListener("touchend",_t,{passive:!0}),window.addEventListener("touchcancel",_t,{passive:!0})),window.addEventListener("resize",ur,{passive:!0}),window.addEventListener("transitionrun",Mt,{capture:!0,passive:!0}),window.addEventListener("transitionend",bt,{capture:!0,passive:!0}),window.addEventListener("transitioncancel",bt,{capture:!0,passive:!0}),"scroll"===Cn&&(window.addEventListener("wheel",On,{capture:!0,passive:!0}),window.addEventListener("touchmove",On,{capture:!0,passive:!0}),window.addEventListener("keydown",On,{capture:!0}),window.addEventListener("scroll",Jt,{capture:!0,passive:!0}),window.addEventListener("scrollend",Zt,{passive:!0})),e.canvas.value?.addEventListener("webglcontextlost",or),e.canvas.value?.addEventListener("webglcontextrestored",lr),Ct(),await hr(C(e.wallpaperUrl),a),At()}catch(i){dr(a)}}function wr(n){if(C(e.active))return n.matches?(cr(),void Kn("fallback")):void xr()}const yr=matchMedia("(prefers-reduced-transparency: reduce)");return yr.addEventListener("change",wr),document.addEventListener("visibilitychange",rr),window.addEventListener("blur",ar),window.addEventListener("focus",ir),window.addEventListener("pageshow",ir),U((()=>[C(e.active),C(e.wallpaperUrl)]),(async([e,n],t)=>{if(e)return ue&&n!==t?.[1]?$.value===n&&ee.value===Et(n)?void rt():void(await fr()):void(ue||(await A(),await xr()));cr()}),{immediate:!0}),U((()=>[C(e.pendingWallpaperUrl??""),C(e.pendingWallpaperRevision??0)]),(([e,n])=>{vr(e,n)}),{immediate:!0}),U((()=>C(e.previousWallpaperUrl??"")),(e=>{!e&&ue&&de&&(nt(),lt(performance.now(),!1))}),{flush:"sync"}),U((()=>C(e.appearance)),(async(n,t)=>{if(!ue)return;const a=()=>{if(!ue||C(e.appearance)!==n)return;const t=s(n,C(e.transparencyStrength??r));ue.uniforms.uAppearance.value=J(n),ue.uniforms.uBackgroundVisibility.value=t.backgroundVisibility,ue.uniforms.uDynamicsOnly.value=Un()?1:0,ue.uniforms.uFrostDetailLevel.value=t.frostDetailLevel,ue.uniforms.uSurfaceDensity.value=t.surfaceDensity,ue.uniforms.uTintDensity.value=t.tintDensity},i=C(e.wallpaperUrl),o=C(e.quality),l=C(e.routeKey);if(Y(t??n,o,l,i)!==Y(n,o,l,i))return kt(),await fr(0,a),void(C(e.appearance)===n&&At());a(),gt()})),U((()=>C(e.quality)),(async(n,t)=>{if(!ue)return;const r=a(t,C(e.routeKey)),i=a(n,C(e.routeKey)),o=()=>{ue&&C(e.quality)===n&&(ue.uniforms.uMaxRefractionPixels.value=f(i.maxRefractionPixels,C(e.deformationStrength??Lt())),ue.uniforms.uQuality.value="high"===n?1:0,ue.uniforms.uTrailCount.value=i.trailCount,Xe=!1,Xn(),It(),ot(),Ct())};if(!Ut(r,i))return o(),void st();kt(),await fr(0,o),C(e.quality)===n&&At()})),U((()=>C(e.tintColor)),(e=>{ue&&(ue.uniforms.uTintColor.value.set(e),st())})),U((()=>[C(e.translationStrength??Lt()),C(e.deformationStrength??Lt()),C(e.flowStrength??Lt()),C(e.reflectionStrength??r),C(e.transparencyStrength??r),C(e.transmissionStrength??r)]),(([n,t,r,a,i,o])=>{if(!ue)return;ue.uniforms.uTranslationStrength.value=c(n),ue.uniforms.uDeformationStrength.value=v(t),ue.uniforms.uFlowStrength.value=m(r),ue.uniforms.uMotionExpansion.value=p(r),ue.uniforms.uMaxRefractionPixels.value=f(Pt().maxRefractionPixels),ue.uniforms.uReflectionStrength.value=d(a);const u=s(C(e.appearance),i);if(ue.uniforms.uBackgroundVisibility.value=u.backgroundVisibility,ue.uniforms.uFrostDetailLevel.value=u.frostDetailLevel,ue.uniforms.uSurfaceDensity.value=u.surfaceDensity,ue.uniforms.uTintDensity.value=u.tintDensity,ue.uniforms.uTransmissionStrength.value=l(o),ue.uniforms.uFlowStrength.value<=0&&Xe){Xe=!1,Xn(),_e=0;for(const e of ue.uniforms.uTrail.value)e.z=0}st()})),U((()=>C(e.pageMotion?.revision??0)),(()=>{if(!ue||"scroll"!==Cn)return;const e=performance.now();Ct(),mt(e,!1),lt(e,!1)}),{flush:"sync"}),U((()=>[C(e.pageMotion?.active??!1),C(e.pageMotion?.epoch??0)]),(([e,n])=>{ue&&"scroll"===Cn&&e&&(Rn=!1,gt(n))}),{flush:"sync"}),U((()=>C(e.routeKey)),(async(n,t)=>{const r=Pt(t??""),a=C(e.wallpaperUrl),i=C(e.appearance),o=C(e.quality);if(Y(i,o,t??"",a)!==Y(i,o,n,a)&&kt(),ue&&"scroll"===Cn&&e.pageMotion){Rn=!1,Wn=C(e.pageMotion.epoch);const n=performance.now();mt(n,!1),lt(n,!1)}if(await A(),ue){const t=Pt(n);if(Ct(),Ut(r,t))return await fr(0,Ct),void(C(e.routeKey)===n&&At())}"scroll"===Cn&&e.pageMotion?gt(C(e.pageMotion.epoch)):ht()})),L((()=>{yr.removeEventListener("change",wr),document.removeEventListener("visibilitychange",rr),window.removeEventListener("blur",ar),window.removeEventListener("focus",ir),window.removeEventListener("pageshow",ir),cr()})),{activatePreparedWallpaper:function(e,n,t,r){if(!gr(e,n,t)||!Pe)return!1;const a={activatedRevision:n,activatedUrl:e,previousHasWallpaperTexture:ve,previousPreparationKey:ee.value,previousRevision:Z.value,previousUrl:$.value},i=Pe;return Pe=null,ne.value="",te.value=0,re.value="",be+=1,pr(i.texture,i.frostedTarget,i.width,i.height,i.hasWallpaperTexture,i.toneProfile,r,!0),Me=ge?a:null,$.value=e,Z.value=n,ee.value=t,mt(r,!1),It(),lt(r,!1),Kn("ready"),rt(),!0},activeWallpaperPreparationKey:ee,activeWallpaperRevision:Z,activeWallpaperUrl:$,canActivatePreparedWallpaper:gr,failedWallpaperPreparationKey:oe,failedWallpaperRevision:ie,failedWallpaperUrl:ae,preparedWallpaperPreparationKey:re,preparedWallpaperUrl:ne,preparedWallpaperRevision:te,renderedFrames:V,rollbackPreparedWallpaperActivation:function(e,n){const t=Me;if(!(ue&&de&&ge&&t&&t.activatedUrl===e&&t.activatedRevision===n&&$.value===e&&Z.value===n))return!1;jn();const r=de,a=fe;return de=ge,fe=xe,pe=we,me=ye,he=Se,ge=null,xe=null,we=pe,ye=me,Se=he,Te=0,Me=null,$.value=t.previousUrl,Z.value=t.previousRevision,ee.value=t.previousPreparationKey,ue.uniforms.uTexture.value=de,ue.uniforms.uFrostedTexture.value=fe?.texture??de,ue.uniforms.uPreviousTexture.value=de,ue.uniforms.uPreviousFrostedTexture.value=fe?.texture??de,ue.uniforms.uWallpaperExposure.value=he,ue.uniforms.uPreviousWallpaperExposure.value=he,ue.uniforms.uTextureMix.value=1,ve=t.previousHasWallpaperTexture,Hn(),ue.uniforms.uHasFrostedTexture.value=t.previousHasWallpaperTexture&&fe?1:0,Dt(),It(),et(r,a),lt(performance.now(),!1),!0},state:n}}let ee,ne,te,re,ae,ie,oe,le,ue,se,ce;({defineComponent:ee}=await e("vue"));({unref:ne,createElementVNode:te,Fragment:re,openBlock:ae,createElementBlock:ie}=await e("vue"));oe=["data-state"];le=["data-state"];({ref:ue,watchEffect:se,onScopeDispose:ce}=await e("vue"));de=ee({__name:"GlassOpticalLayer",props:{appearance:{},deformationStrength:{},flowStrength:{},quality:{},reflectionStrength:{},transparencyStrength:{},transmissionStrength:{},translationStrength:{},routeKey:{},tintColor:{},transitionDuration:{},transitionStartedAt:{},wallpaperUrl:{},previousWallpaperUrl:{},pendingWallpaperUrl:{},pendingWallpaperRevision:{},activateWallpaperRevision:{}},emits:["wallpaperPrepared","wallpaperPreparationFailed","wallpaperActivated","wallpaperActivationFailed"],setup(e,{emit:t}){const r=e,a=t,i=ue(null),o=ue(null),l=V(),u=n(),s=z(),c=Z({active:!0,appearance:()=>r.appearance,canvas:i,deformationStrength:()=>r.deformationStrength,flowStrength:()=>r.flowStrength,interactionSource:l,quality:()=>r.quality,reflectionStrength:()=>r.reflectionStrength,transparencyStrength:()=>r.transparencyStrength,transmissionStrength:()=>r.transmissionStrength,translationStrength:()=>r.translationStrength,routeKey:()=>r.routeKey,tintColor:()=>r.tintColor,transitionDuration:()=>r.transitionDuration,transitionStartedAt:()=>r.transitionStartedAt,wallpaperUrl:()=>r.wallpaperUrl,wallpaperSourceCache:s,previousWallpaperUrl:()=>r.previousWallpaperUrl,pendingWallpaperUrl:()=>r.pendingWallpaperUrl??"",pendingWallpaperRevision:()=>r.pendingWallpaperRevision??0,surfaceSpace:"fixed",syncDocumentState:!1}),d=Z({active:!0,appearance:()=>r.appearance,canvas:o,deformationStrength:()=>r.deformationStrength,flowStrength:()=>r.flowStrength,interactionSource:l,pageMotion:u.reader,quality:()=>r.quality,reflectionStrength:()=>r.reflectionStrength,transparencyStrength:()=>r.transparencyStrength,transmissionStrength:()=>r.transmissionStrength,translationStrength:()=>r.translationStrength,routeKey:()=>r.routeKey,tintColor:()=>r.tintColor,transitionDuration:()=>r.transitionDuration,transitionStartedAt:()=>r.transitionStartedAt,wallpaperUrl:()=>r.wallpaperUrl,wallpaperSourceCache:s,previousWallpaperUrl:()=>r.previousWallpaperUrl,pendingWallpaperUrl:()=>r.pendingWallpaperUrl??"",pendingWallpaperRevision:()=>r.pendingWallpaperRevision??0,surfaceSpace:"scroll",syncDocumentState:!1}),f=ue("loading");se((()=>{const e=[c.state.value,d.state.value],n=e.every((e=>"ready"===e))?"ready":e.some((e=>"loading"===e))?"loading":"fallback";H(f,n)}));let p="";se((()=>{const e=r.pendingWallpaperUrl,n=r.pendingWallpaperRevision??0,t=Y(r.appearance,r.quality,r.routeKey,e??""),i=`${n}:${t}:${e}`;Boolean(e)&&n>0&&"ready"===c.state.value&&"ready"===d.state.value&&c.preparedWallpaperUrl.value===e&&c.preparedWallpaperRevision.value===n&&c.preparedWallpaperPreparationKey.value===t&&d.preparedWallpaperUrl.value===e&&d.preparedWallpaperRevision.value===n&&d.preparedWallpaperPreparationKey.value===t&&i!==p&&(p=i,a("wallpaperPrepared",e,n))}));let m="";se((()=>{const e=r.pendingWallpaperUrl??"",n=r.pendingWallpaperRevision??0,t=Y(r.appearance,r.quality,r.routeKey,e),i=`${n}:${t}:${e}`,o=[c,d].some((r=>r.failedWallpaperUrl.value===e&&r.failedWallpaperRevision.value===n&&r.failedWallpaperPreparationKey.value===t));e&&n>0&&o&&i!==m&&(m=i,a("wallpaperPreparationFailed",e,n))}));let v=null,h="",g="",x="";function w(e,n){for(const t of[c,d])try{t.rollbackPreparedWallpaperActivation(e,n)}catch{}}return se((()=>{const e=r.pendingWallpaperUrl,n=r.pendingWallpaperRevision??0,t=r.activateWallpaperRevision??0,i=Y(r.appearance,r.quality,r.routeKey,e??""),o=`${n}:${i}:${e}`;Boolean(e)&&n>0&&t===n&&"ready"===c.state.value&&"ready"===d.state.value&&c.preparedWallpaperUrl.value===e&&c.preparedWallpaperRevision.value===n&&c.preparedWallpaperPreparationKey.value===i&&d.preparedWallpaperUrl.value===e&&d.preparedWallpaperRevision.value===n&&d.preparedWallpaperPreparationKey.value===i&&o!==g&&o!==x&&o!==h&&(null!==v&&cancelAnimationFrame(v),h=o,v=requestAnimationFrame((e=>{v=null,h="";const n=r.pendingWallpaperUrl??"",t=r.pendingWallpaperRevision??0,i=Y(r.appearance,r.quality,r.routeKey,n);if(`${t}:${i}:${n}`===o&&r.activateWallpaperRevision===t&&c.canActivatePreparedWallpaper(n,t,i)&&d.canActivatePreparedWallpaper(n,t,i)){try{const r=c.activatePreparedWallpaper(n,t,i,e),l=r&&d.activatePreparedWallpaper(n,t,i,e);if(!r||!l)return w(n,t),x=o,void a("wallpaperActivationFailed",n,t)}catch{return w(n,t),x=o,void a("wallpaperActivationFailed",n,t)}g=o,a("wallpaperActivated",n,t,e)}})))})),ce((()=>{null!==v&&cancelAnimationFrame(v),H(f,"fallback")})),(e,n)=>(ae(),ie(re,null,[te("canvas",{ref_key:"fixedCanvas",ref:i,class:"glass-optical-layer glass-optical-layer--fixed","aria-hidden":"true","data-presentation-space":"fixed","data-state":ne(c).state.value},null,8,oe),te("canvas",{ref_key:"scrollCanvas",ref:o,class:"glass-optical-layer glass-optical-layer--scroll","aria-hidden":"true","data-presentation-space":"scroll","data-state":ne(d).state.value},null,8,le)],64))}})});export{de as default,__mp_tla};