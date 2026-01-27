/**
 * Generate topographic contour SVG background using d3-contour
 * This creates organic, realistic contour lines like bathymetric/topographic maps
 */

import * as d3Contour from 'd3-contour';
import * as d3Geo from 'd3-geo';
import { writeFileSync } from 'fs';

// Configuration - Larger size to reduce tiling
const width = 2400;
const height = 1800;
const thresholds = 15; // Number of contour levels for more detail
const randnoise = () => 1 + (Math.log10(1 + Math.random()) - 0.15)

// Generate Perlin-like noise using multiple sine waves (simplex noise approximation)
function generateNoise(width, height, seed = 67) {
    const values = new Array(width * height);

    // Parameters for multiple octaves of noise - lower frequencies for larger patterns
    const octaves = [
        { freq: 0.003, amp: 1.0 },
        { freq: 0.006, amp: 0.5 },
        { freq: 0.012, amp: 0.25 },
        { freq: 0.024, amp: 0.125 },
    ];

    for (let j = 0; j < height; j++) {
        for (let i = 0; i < width; i++) {
            let value = 0;

            for (const oct of octaves) {
                // Use combination of sin waves to approximate noise
                value += oct.amp * (
                    Math.sin(i * oct.freq * 2.5 + seed) *
                    Math.cos(j * oct.freq * 3.1 + seed * 0.7 * randnoise()) +
                    Math.sin((i + j) * oct.freq * 1.8 + seed * 1.3 * randnoise()) * 0.5 +
                    Math.cos((i - j * 0.7) * oct.freq * 2.2 + seed * 0.5 * randnoise()) * 0.3
                );
            }

            // Add some radial peaks to simulate islands/mountains
            const cx1 = width * 0.3 * randnoise(), cy1 = height * 0.35 * randnoise();
            const cx2 = width * 0.7 * randnoise(), cy2 = height * 0.6 * randnoise();
            const cx3 = width * 0.5 * randnoise(), cy3 = height * 0.8 * randnoise();

            const dist1 = Math.sqrt((i - cx1) ** 2 + (j - cy1) ** 2);
            const dist2 = Math.sqrt((i - cx2) ** 2 + (j - cy2) ** 2);
            const dist3 = Math.sqrt((i - cx3) ** 2 + (j - cy3) ** 2);

            value += Math.max(0, 1.5 - dist1 / 80 * randnoise());
            value += Math.max(0, 1.2 - dist2 / 100 * randnoise());
            value += Math.max(0, 0.8 - dist3 / 60);

            values[i + j * width] = value;
        }
    }

    return values;
}

// Generate contours
const values = generateNoise(width, height);
const contours = d3Contour.contours()
    .size([width, height])
    .thresholds(thresholds);

const contourData = contours(values);

// Convert to SVG paths
const path = d3Geo.geoPath();

// Generate SVG for light mode (gray strokes)
function generateSVG(strokeColor, strokeWidth = 0.6) {
    let paths = '';

    for (const contour of contourData) {
        const d = path(contour);
        if (d) {
            paths += `  <path d="${d}" />\n`;
        }
    }

    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}">
  <g fill="none" stroke="${strokeColor}" stroke-width="${strokeWidth}">
${paths}  </g>
</svg>`;
}

// Generate both light and dark mode versions
const lightSVG = generateSVG('#777', 0.8);
const darkSVG = generateSVG('#444', 0.8);

// Save raw SVG files
writeFileSync('src/assets/contour-light.svg', lightSVG);
writeFileSync('src/assets/contour-dark.svg', darkSVG);

// URL encode for CSS embedding
function urlEncodeSVG(svg) {
    return svg
        .replace(/\n/g, '')
        .replace(/\s+/g, ' ')
        .replace(/"/g, "'")
        .replace(/#/g, '%23')
        .replace(/</g, '%3C')
        .replace(/>/g, '%3E');
}

const lightEncoded = urlEncodeSVG(lightSVG);
const darkEncoded = urlEncodeSVG(darkSVG);

console.log('=== LIGHT MODE CSS ===');
console.log(`background-image: url("data:image/svg+xml,${lightEncoded}");`);
console.log(`background-size: ${width}px ${height}px;`);
console.log('');
console.log('=== DARK MODE CSS ===');
console.log(`background-image: url("data:image/svg+xml,${darkEncoded}");`);
console.log(`background-size: ${width}px ${height}px;`);

console.log('\n✓ SVG files saved to src/assets/');
