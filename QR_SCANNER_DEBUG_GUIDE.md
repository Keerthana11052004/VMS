# QR Scanner Debug Guide

## 🔧 How to Debug the QR Scanner Issue

### Step 1: Open Browser Console
1. Go to http://localhost:5000/check_in_approval
2. Press **F12** (or Right-click → Inspect → Console tab)
3. Clear the console (trash icon)

### Step 2: Test QR Scanning
1. Click "Scan QR for Check-in" button
2. Allow camera permissions
3. Point camera at a QR code
4. **Watch the console carefully** for these messages:

#### If QR scans successfully, you'll see:
```
✅ QR CODE SCAN SUCCESS!
📱 Decoded Text: [the scanned value]
📊 Decoded Text Type: string
📏 Decoded Text Length: [number]
```

#### Then you'll see the fetch attempt:
```
🔍 FETCHING VISITOR DETAILS
📝 Visitor ID Parameter: [the value]
🌐 API URL: /get_visitor_details/[value]
📡 Response Status: [200 or 404 or other]
📦 Response Data: [JSON data]
```

### Step 3: Manual Test (Easier!)
Use the **"Debug: Manual Visitor ID Test"** box:

1. Find a Visitor ID from the table below (look at "Visitor ID" column)
2. Copy the exact ID (e.g., "87001")
3. Paste it in the manual test input box
4. Click "Test Lookup"
5. **Watch console for detailed logs**

### Step 4: Analyze Console Output

#### ✅ If it works:
- You'll see "✅ Visitor found successfully!"
- Visitor details card will appear

#### ❌ If it fails, check:
1. **Response Status 404** = Visitor ID doesn't exist in database
2. **"Visitor not found!"** message = ID format mismatch
3. **Exception errors** = JavaScript or network issue

### Step 5: Common Issues & Solutions

#### Issue: QR scans but says "Visitor not found"
**Cause**: QR code contains different data than what's in database
**Solution**: 
- Look at console: "📱 Decoded Text:" shows what was scanned
- Compare with "Visitor_ID" in database
- They must match exactly!

#### Issue: QR doesn't scan at all
**Cause**: Camera not working or QR code quality
**Solution**:
- Check console for camera errors
- Try better lighting
- Hold QR code steady
- Ensure QR code is clear and not blurry

#### Issue: "Response Status: 500"
**Cause**: Server-side error
**Solution**: 
- Check Flask terminal for Python errors
- Database connection issue

## 📋 Checklist for User

Please check and report:

1. [ ] Does the manual test work? (Try visitor ID from table)
2. [ ] What does "📱 Decoded Text:" show when you scan?
3. [ ] What is the "📡 Response Status:" number?
4. [ ] Does the Visitor ID in the table match what QR code contains?
5. [ ] Any red error messages in console?

## 🎯 Quick Test Command

In browser console, type:
```javascript
fetchVisitorDetailsAndShowActions('87001')
```
Replace '87001' with an actual Visitor ID from your table.

## 📸 What to Share

If issue persists, share screenshot of:
1. Full browser console after scanning attempt
2. The visitor list table showing Visitor IDs
3. The QR code being scanned (if possible)

