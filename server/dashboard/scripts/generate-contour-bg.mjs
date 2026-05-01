/**
 * Generate topographic contour SVG background using d3-contour
 * This creates organic, realistic contour lines like bathymetric/topographic maps
 */

import * as d3Contour from 'd3-contour';
import * as d3Geo from 'd3-geo';
import { writeFileSync } from 'fs';

// Configuration
const renderWidth = 2400;  // Final SVG width
const renderHeight = 1800; // Final SVG height
const dataWidth = 800;     // Grid resolution (lower = smoother/faster)
const dataHeight = 600;
const thresholds = 17;     // Number of contour levels

// Generate noise on a lower resolution grid for smoothness and performance
function generateNoise(width, height, seed = 67) {
    const values = new Array(width * height);

    // Parameters for multiple octaves of noise
    const octaves = [
        { freq: 0.008, amp: 1.0 },
        { freq: 0.016, amp: 0.5 },
        { freq: 0.032, amp: 0.25 },
        { freq: 0.064, amp: 0.125 },
    ];

    // Seeded random variation for peaks
    const getVariation = (s) => 1 + (Math.sin(s * 1000) * 0.2);

    for (let j = 0; j < height; j++) {
        for (let i = 0; i < width; i++) {
            let value = 0;

            for (const oct of octaves) {
                // Use deterministic combination for noise (smooth)
                value += oct.amp * (
                    Math.sin(i * oct.freq * 2.5 + seed) *
                    Math.cos(j * oct.freq * 3.1 + seed * 0.7) +
                    Math.sin((i + j) * oct.freq * 1.8 + seed * 1.3) * 0.5 +
                    Math.cos((i - j * 0.7) * oct.freq * 2.2 + seed * 0.5) * 0.3
                );
            }

            // Add smooth radial peaks (islands)
            const cx1 = width * 0.3 * getVariation(seed), cy1 = height * 0.35;
            const cx2 = width * 0.7 * getVariation(seed + 1), cy2 = height * 0.6;
            const cx3 = width * 0.5 * getVariation(seed + 2), cy3 = height * 0.8;

            const dist1 = Math.sqrt((i - cx1) ** 2 + (j - cy1) ** 2);
            const dist2 = Math.sqrt((i - cx2) ** 2 + (j - cy2) ** 2);
            const dist3 = Math.sqrt((i - cx3) ** 2 + (j - cy3) ** 2);

            value += Math.max(0, 1.5 - dist1 / (width * 0.1));
            value += Math.max(0, 1.2 - dist2 / (width * 0.12));
            value += Math.max(0, 0.8 - dist3 / (width * 0.08));

            values[i + j * width] = value;
        }
    }
    return values;
}

console.log(`Generating noise grid (${dataWidth}x${dataHeight})...`);
const values = generateNoise(dataWidth, dataHeight);

console.log(`Computing contours (thresholds: ${thresholds})...`);
const contours = d3Contour.contours()
    .size([dataWidth, dataHeight])
    .thresholds(thresholds);

const contourData = contours(values);

// Scale up the paths from data coordinates to render coordinates
const scaleX = renderWidth / dataWidth;
const scaleY = renderHeight / dataHeight;
const path = d3Geo.geoPath().projection(d3Geo.geoIdentity().scale(scaleX));

function generateSVG(strokeColor, strokeWidth = 0.6) {
    let paths = '';
    for (const contour of contourData) {
        const d = path(contour);
        if (d) {
            paths += `  <path d="${d}" />\n`;
        }
    }

    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${renderWidth} ${renderHeight}">
  <g fill="none" stroke="${strokeColor}" stroke-width="${strokeWidth}">
${paths}  </g>
</svg>`;
}

console.log('Generating SVG templates...');
const lightSVG = generateSVG('#777', 2);
const darkSVG = generateSVG('#444', 2);

console.log('Saving SVG files to src/assets/...');
writeFileSync('src/assets/contour-light.svg', lightSVG);
writeFileSync('src/assets/contour-dark.svg', darkSVG);

console.log('\n✓ Topographic backgrounds generated successfully!');
console.log(`- Resolution: ${renderWidth}x${renderHeight}`);
console.log(`- Data Resolution: ${dataWidth}x${dataHeight}`);
console.log(`- Light mode: src/assets/contour-light.svg`);
console.log(`- Dark mode: src/assets/contour-dark.svg`);
