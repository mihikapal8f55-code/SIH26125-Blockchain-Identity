// ==================================================================
// SIH26125 — APP INIT
//
// Load order matters. ui.js and app.js define the helpers the v6
// modules call; main.js owns the sequence.
// ==================================================================

document.addEventListener('DOMContentLoaded', () => {
    // 1. Shell, theme, navigation, keyboard map, activity log.
    initShell();

    // 2. Demo-field filler, tab keyboard nav, result stream.
    initV5();

    // 3. Restructure the DOM before anything indexes it:
    //    - flatten the column wrappers into one grid per workspace
    //    - bucket the 84 cards into named, collapsible groups
    //    - add archetype tags and workspace toolbars
    //    - take over gotoSection for deep links + back/forward
    if (window.ORGANIZE) ORGANIZE.init();

    // 4. Result console: wrap all result containers in verdict chips.
    //    Runs after ORGANIZE so card titles are in their final position.
    if (window.CONSOLE) CONSOLE.init();

    // 5. Command palette last: it indexes the final DOM.
    if (window.PALETTE) PALETTE.init();

    // 6. Chain data. Results land in the console via the observer.
    loadBlockchainData();
});
