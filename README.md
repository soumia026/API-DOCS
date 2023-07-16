# API-DOCS
## General information
- `Node.js` : open-source, server-side JavaScript runtime that allows you to run JavaScript code on a computer/server rather than just in a web browser. Node is fast but it does not support request handling, HTTP methods or serving files so this where Express JS comes to the picture.
- `Express.js` : A Node.js framework designed for building APIs, web applications and cross-platform mobile apps. Express is fast because there is no structural way to write the code.
- `Middlewares` : a piece of code that sits between the server and the application's routes or endpoints. Think of it as a layer of functionality that can process or modify requests and responses as they flow through your web application. For example, we have a common use middlware:
  
  ```js
  app.use(express.json())
  ```
  Previous middleware is a built-in middleware provided by the Express.js framework. It is used to parse incoming requests with JSON payloads.
- `Controllers` and `Routes` : is simply a way to organize our server, so that things don't get very messy, controllers are modules that handle the logic and behavior of a specific route or endpoint in an application.
  Routes are URLs or endpoints that users can access to interact with our application.
- `Mongoose` : is an Object Data Modeling (ODM) library for Node.js that provides a higher-level abstraction layer for MongoDB. Mongoose offers features like data validation, middleware support, and query building utilities.
- `AsyncHandler` : a simple library that helps you handle asynchronous functions in an Express.js middleware or route handler. It replaces `try` and `catch` blocks.
## First setup packages
> express, dotenv, nodemon, morgan 
```js
require('dotenv').config()
```
```js
// http logger
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'))
}
```
<br/>
<br/>

## package.json commands
```js
npm init -y
```
### packge.json configuration
```js
    "start": "NODE_ENV=production node server",
    "dev": "nodemon server"
```
### git initialisation
- `git init` in the root
- add a `gitignore` file in the root and add `.env` file and `node_modules/`
<br/>
<br/>

## Restful API structure
![Capture](https://user-images.githubusercontent.com/77200870/183821759-fbdec3c3-613f-484d-9ca0-2413cf2a9e65.PNG)
<br/>
<br/>

## Routes and controllers setup
> In the server file
```js
app.use(base route, routesFile)
```
> In the routes file
```js
router.method(sub route, controller)
```
> Install `express-async-handler`<br/>
> In the controller file<br/>
> Wrap all the methods
```js
const asyncHandler = require('express-async-handler')

exports.methodName = asyncHandler(async(req, res) => {
    // login goes in here
})
```
<br/>
<br/>

## Connecting to the database
> Install mongoose

> Put the connection URI in the `.env` file

> Inside the `config` folder create a `db.js` file
```js
const mongoose = require('mongoose')

const connectDB = async (url) => {
    return await mongoose.connect(url)
}

module.exports = connectDB
```
> In `server.js` add the db connection function
```js
const PORT = process.env.PORT || 5000

const start = async () => {
    try {
        const conn = await connectDB(process.env.MONGO_URI)
        console.log(`MongoDB connected successfully: ${conn.connection.host}`)
        app.listen(PORT, () => {
            console.log(`Server listening in ${process.env.NODE_ENV} mode on port ${PORT}`)
        })
    } catch (error) {
        console.log(error)
        process.exit(1)
    }
}

start()
```
<br/>
<br/>

## Mongoose Models
> Add the models in a `models` folder (as a convention they must be capatilized)
```js
const mongoose = require('mongoose')

const ModelSchema = new mongoose.Schema({
    // model body
}, {timestamps: true})

const Model = mongoose.model('Model', ModelSchema)

module.exports = Model
```
- `{timestamps: true}` : is an option that can be passed to a schema to automatically add two fields `createdAt` and `updatedAt`, to each document in the collection.
### Model proprties
| Option | Values |
| ------ | ----------- |
| **type**   | String, Number, [String], [Number] |
| **required**   | true, false |
| **default**   | true, 'no-inage.jpg' |
| **unique**   | true, false |
| **select**   | true, false |
| **enum**   | ['PWN', 'RE', 'Malware Development'] |
| **trim**   | true, false |
| **maxlength**   | 50, [100, 'error message'] |
| **minlength**   | 50, [100, 'error message'] |
| **match**   | regex, [regex, 'error message'] |
| **min**   | 1, 2 |
| **max**   | 10, 100 |
| **ObjectId**   | mongoose.Schema.Types.ObjectId |

### Model Methods
- create(object)
- find({...})
- findById(id)
- findByIdAndUpdate(id, {new data}, {new: true, runValidators: true})
- findByIdAndDelete(id)
### Model Hooks
```js
// uses normal function syntax to use the this keyword in the appropriate way
ModelSchema.pre('save', function(next) {
  this.slug = slugify(this.name, { lower: true })
  next() // must call next
})
```

<br/>
<details><summary>Show full example</summary>
<p>
    
```js
  const BootcampSchema = new mongoose.Schema({
      name: {
        type: String,
        required: [true, 'Please add a name'],
        unique: true,
        trim: true,
        maxlength: [50, 'Name can not be more than 50 characters']
      },
      slug: String,
      description: {
        type: String,
        required: [true, 'Please add a description'],
        maxlength: [500, 'Description can not be more than 500 characters']
      },
      website: {
        type: String,
        match: [
            /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/,
            'Please use a valid URL with HTTP or HTTPS'
        ]
      },
      phone: {
        type: String,
        maxlength: [20, 'Please enter a valid phone number']
      },
      email: {
        type: String,
        match: [
            /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
            'Please enter a valid email'
        ]
      },
      address: {
        type: String,
        required: [true, 'Please enter an address']
      },
      location: {
        type: {
            type: String,
            enum: ['Point'],
            required: true,
        },
        coordinates: {
            type: [Number],
            required: true,
            index: '2dshpere'
        },
        formattedAddress: String,
        street: String,
        city: String,
        state: String,
        zipcode: String,
        country: String,
      },
      carrers: {
        type: [String],
        enum: [
            'Web Development',
            'Mobile Development',
            'UI/UX',
            'Data Science',
            'Business',
            'Other'
        ]
      },
      averageRating: {
        type: Number,
        min: [1, 'Rating must be at least 1'],
        max: [10, 'Rating can not be more than 10'],
      },
      averageCost: Number,
      photo: {
        type: String,
        default: 'no-photo.jpg'
      },
      housing: {
        type: Boolean,
        default: false
      },
      jobAssistance: {
        type: Boolean,
        default: false
      },
      jobGuarantee: {
        type: Boolean,
        default: false
      },
      acceptGi: {
        type: Boolean,
        default: false,
      }
}, {timestamps: true})
```
    
</p>
</details>
<br/>
<br/>

## Body parser
> Parse the json data that comes from requests into javascript

> In `server.js`
```js
app.use(express.json())
```
<br/>
<br/>

## Custom error handling
> Inside `middlewares` folder, `errorHandler.js`
```js
const errorHandler = (err, req, res, next) => {
    const statusCode = res.statusCode === 200 ? 500 : res.statusCode
    res.status(statusCode).json({
        message: err.message,
        stack: process.env.NODE_ENV === 'production' ? null : err.stack
    })
}

const notFound = (req, res, next) => {
    const error = new Error(`Not Found ${req.originalUrl}`)
    res.status(404)
    next(error)
}

module.exports = {
    errorHandler,
    notFound,
}
```
> To use it, inside the controllers just throw new Error('error message')<br/>
> Include and `app.use` both methods in `server.js`
<br/>
<br/>

## Geocoding
> Install `node-geocoder`

> Add `GEOCODER_PROVIDER` and `GEOCODER_API_KEY` to the `.env` file

> Add the utility function
```js
const NodeGeocoder = require('node-geocoder')

const options = {
    provider: process.env.GEOCODER_PROVIDER,
    httpAdapter: 'https',
    apiKey: process.env.GEOCODER_API_KEY,
    formatter: null,
}

const geocoder = NodeGeocoder(options)

module.exports = geocoder
```
> Add the model hook on pre save
```js
// Geocode & create lcoation field
ModelSchema.pre('save', async function(next) {
  const loc = await geocoder.geocode(this.address)

  // GeoJSON object
  this.location = {
    type: 'Point',
    coordinates: [loc[0].longitude, loc[0].latitude],
    formattedAddress: loc[0].formattedAddress,
    street: loc[0].streetName,
    city: loc[0].city,
    state: loc[0].stateCode,
    zipcode: loc[0].zipcode,
    country: loc[0].countryCode,
  }

  // Do not save address in DB, we have the location
  this.address = undefined

  next()
})
```
### Application
> Get the zip code and distance

> Geocode using the zipcode

> Get the radius by dividing the distance by earth radius

> Query for the location field using `$geoWithin`
```js
    // route : /api/v1/bootcamps/:zipcode/:distance
    const { zipcode, distance } = req.params

    // Get lat/lng from the geocoder
    const loc = await geocoder.geocode(zipcode)
    const lat = loc[0].latitude
    const lng = loc[0].longitude

    // Calculate radius using radians : Devide distance by radius of earth
    // Earth radius : 6378km
    const radius = Number(distance) / 6378

    const bootcamps = await Bootcamp.find({
        location: {
            $geoWithin: {
                $centerSphere: [ [lng, lat], radius ]
            }
        }
    })
```
<br/>
<br/>

## Advanced Filtering

### Selecting certain documents
> Create a queryStr which holds the stringified version on `req.query`

> Add $ to the usual querying options

> Parse the querying string and run a query

```js
let query

// copy of req.query
let reqQuery = { ...req.query }

// exclude special-meaning fields
const excluded = ['select', 'sort']
excluded.forEach(param => delete reqQuery[param])

let queryStr = JSON.stringify(reqQuery)

queryStr = queryStr.replace(/\b(gt|gte|lt|lte|in)\b/, match => `$${match}`)

query = Model.find(JSON.parse(queryStr))

const bootcamps = await query
```
### Selecting certain fields within documents
```js
if (req.query.select) {
    const fields = req.query.select.split(',').join(' ')
    query = query.select(fields)
}
```
### Sort by certain fields
```js
if (req.query.sort) {
    const sortBy = req.query.sort.split(',').join(' ')
    query = query.sort(sortBy)
} else {
    query = query.sort('-createdAt')
}
```
### pagination
```js
const page = parseInt(req.query.page, 10) || 1
const limit = parseInt(req.query.limit, 10) || 25
const startIndex = (page - 1) * limit
const endIndex = page * limit
const total = await Model.countDocuments()

query = query.skip(startIndex).limit(limit)

// run the query

const pagination = {}

if (startIndex > 0) {
    pagination.prev = {
        page: page - 1,
        limit,
    }
}

if (endIndex < total) {
    pagination.next = {
        page: page + 1,
        limit,
    }
}

// add pagination object to the response
```
<br/>
<br/>

## Merging Routes
> Let's say we have these two routes: `/api/v1/courses` and `/api/v1/bootcamps/:bootcampId/courses`, we can use one controller method for both of them.

> In the courses routes file, it's simple

> In the bootcamps routes file, we require the `coursesRoutes` file, then
```js
router.use('/:bootcampId/courses', courseRoutes)
```

> In the `courseRoutes` we merge the routes
```js
const router = express.Router({ mergeParams: true })
```
> Then the methods on the `/` route in `courseRoutes` will be executed
> The controller method
```js
    let query

    if (req.params.bootcampId) {
        query = Course.find({ bootcamp: req.params.bootcampId })
    } else {
        query = Course.find()
    }

    const courses = await query

    res.status(200).json({
        success: true,
        count: courses.length,
        data: courses,
    })
```
> Also if we wanted to create a course for a specific bootcamp, we can use the same route with a `POST` method
```js
    req.body.bootcampId = req.params.bootcampId

    // Make sure that the bootcamp exists before create a course associated with it
    const bootcamp = await Bootcamp.findById(req.params.bootcampId)

    if (bootcamp) {
        const course = await Course.create(req.body)
        
        res.status(200).json({
            success: true,
            data: course,
        })
    } else {
        res.status(404)
        throw new Error('Bootcamp not found')
    }
```
<br/>
<br/>

## Populate
> .populate('fieled')
> .populate({ path: 'field', select: 'fields' })
```js
    query = Course.find().populate({
            path: 'bootcamp',
            select: 'name description',
        })
```
<br/>
<br/>

## Virtuals
> Virtuals are document proprties that you can get and set but that do not get presisted to MongoDB

> In the `big` Model(the one that will contain sub documents) we add with `timestamps`

```js
toJSON: { virtuals: true }
toObject: { virtuals: true }
```
> And we add the viruals
```js
BootcampSchema.virtual('courses', {
  ref: 'Course',
  localField: '_id',
  foreignField: 'bootcamp',
  justOne: false,
})
```
> Then in the `big` model's controller, we populate the query with `courses`
```js
query = Bootcamp.find(JSON.parse(queryStr)).populate('courses')
```
<br/>
<br/>

## Cascade-Delete Documnets
> Add a pre remove hook in the main model
```js
// Cascade Delete courses when a bootcamp is deleted
BootcampSchema.pre('remove', async function(next) {
  await this.model('Course').deleteMany({ bootcamp: this._id })
  next()
})
```

> In the controller of the main model, don't use `findByIdAndDelete()`, instead use `findById()` and then `document.remove()`
<br/>
<br/>

## Aggregation
```js
// Static method to get average of course tuitions
CourseSchema.statics.getAverageCost = async function(bootcampId) {
    const obj = await this.aggregate([
        {
            $match: { bootcamp: bootcampId }
        },
        {
            $group: {
                _id: '$bootcamp',
                averageCost: { $avg: 'tuition' }
            }
        }
    ])

    try {
        await this.model('Bootcamp').findByIdAndUpdate(bootcampId, {
            averageCost: Math.ceil(obj[0].averageCost / 10) * 10
        })
    } catch (error) {
        console.error(error)
    }
}

// Call getAverageCost after save
CourseSchema.post('save', function() {
    this.constructor.getAverageCost(this.bootcamp)
})

// Call getAverageCost before remove
CourseSchema.pre('remove', function() {
    this.constructor.getAverageCost(this.bootcamp)
})

```
<br/>
<br/>

## Image Upload
### Upload image locally on the server
> Install `multer`
```js
const express = require('express')
const multer = require('multer')
const path = require('path')

const router = express.Router()

const checkFileType = (file, cb) => {
    const fileTypes = /jpg|jpeg|png/
    const extname = fileTypes.test(path.extname(file.originalname).toLowerCase())
    const mimetype  = fileTypes.test(file.mimetype)

    if (extname && mimetype) {
        return cb(null, true)
    } else {
        cb('Images only!')
    }
}

const storage = multer.diskStorage({
    destination(req, file, cb) {
        cb(null, 'uploads/')
    },
    filename(req, file, cb) {
        cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
    }
})

const upload = multer({
    storage,
    fileFilter: function(req, file, cb) {
        checkFileType(file, cb)
    },
})

router.post('/', upload.single('image'), (req, res) => {
    res.send(`\\${req.file.path}`)
})

module.exports = router
```
### Upload image to Cloudinary
> Install `multer`

> Install `cloudinary`

> Install `multer-storage-cloudinary`
```js
const express = require('express')
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const multer = require('multer')

const router = express.Router()

cloudinary.config({
    cloud_name: "dfnqmhmae",
    api_key: "766665794797967",
    api_secret: "Bm0BfN4p2Rlsn2_3RQZQKqWnDp4",
})

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
      folder: "users_photos",
    },
})

const upload = multer({
    storage: storage,
})

router.post('/', upload.single('image'), (req, res) => {
    res.send(req.file.path)
})

module.exports = router
```
### Image Upload Frontend
```js
    const uploadImageHandler = async (e) => {
        const image = e.target.files[0]
        const formData = new FormData()
        formData.append('image', image)
        setUploading(true)

        try {
            const config = {
                headers: {
                    'Content-Type': 'multipart/form-data',
                }
            }

            const { data } = await axios.post('/api/uploads', formData, config)

            setImage(data)
            setUploading(false)
        } catch (error) {
            console.error(error)
            setUploading(false)
        }
    }
```
<br/>
<br/>

## Authentication
### Packages
> `jsonwebtoken` and `bcryptjs`

### File Structure

> **Route:** /api/v1/auth

> `authControllers` and `authRoutes` files

### Password Encryption
> In the `User` model
```js
// Encrypt password
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        next()
    }

    const salt = await bcrypt.genSalt(10)
    this.password = await bcrypt.hash(this.password, salt)
}) 
```

### User Registration
```js
// @desc        Register user
// @router      POST /api/v1/auth/register
// @access      Public
exports.registerUser = asyncHandler(async (req, res) => {
    const { name, email, password, role } = req.body

    const emailExists = await User.findOne({email})

    if (emailExists) {
        res.status(400)
        throw new Error('User already exists')
    }

    // Create user
    const user = await User.create({
        name,
        email,
        password,
        role
    })
    
    // Generate token
    const token = user.generateJWT()

    if (user) {
        res.status(200).json({success: true, data: user, token})
    } else {
       res.status(422)
       throw new Error('Invalid Input')
    }
})
```

### Token Generation
> In the `User` model
```js
UserSchema.methods.generateJWT = function() {
    return jwt.sign({userId: this._id}, process.env.JWT_SECRET, {expiresIn: '30d'})
}
```

### User Authentication
```js
// @desc        Authenticate user
// @router      POST /api/v1/auth/login
// @access      Public
exports.authUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body

    // Validate email & password
    if (email && password) {
        const user = await User.findOne({email}).select('+password')

        if (user && (await user.matchPassword(password))) {
            res.status(200)
            res.json({
                name: user.name,
                email: user.email,
                role: user.role,
                token: user.generateJWT(),
            })
        } else {
            res.status(401)
            throw new Error('Invalid Credentials') 
        }
    } else {
        res.status(422)
        throw new Error('Invalid Input')
    }
})
```
### Sending token in cookies
> **What Are Cookies?**
>Cookies are small files of information that a web server generates and sends to a web browser. Web browsers store the cookies they receive for a predetermined period of time, or for the length of a user's session on a website. They attach the relevant cookies to any future requests the user makes of the web server.
Cookies help inform websites about the user, enabling the websites to personalize the user experience. For example, ecommerce websites use cookies to know what merchandise users have placed in their shopping carts. In addition, some cookies are necessary for security purposes, such as authentication cookies (see below).
The cookies that are used on the Internet are also called "HTTP cookies." Like much of the web, cookies are sent using the HTTP protocol.

> Install `cookie-parser`

> Include it in `server` and `app.use(cookieParse())`

> In `authController`
```js
// Get token from model, create cookie and send response
const sendTokenResponse = (user, statusCode, res) => {
    const token = user.generateJWT()

    const options = {
        expires: new Date(Date.now() + (30 * 60 * 60 * 24 * 1000)),
        httpOnly: true,
    }

    if (process.env.NODE_ENV === 'production') {
        options.secure = true
    }

    res
        .status(statusCode)
        .cookie('token', token, options)
        .json({
            name: user.name,
            email: user.email,
            role: user.role,
            token: user.generateJWT(),
        })
}
```
> Then whenever we send a successful response, we send it like so
```js
sendTokenResponse(user, 200, res)
```
### Auth Middleware
```js
const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')
const User = require('../models/User')

exports.protect = asyncHandler(async (req, res, next) => {
    let token

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1]
    } else if (req.cookies.token) {
        token = req.cookies.token
    }

    if (!token) {
        res.status(401)
        throw new Error('Not authorized to access this route')
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        req.user = await User.findById(decoded.userId)
    } catch (error) {
        res.status(401)
        throw new Error('Token failed')
    }

    next()
})
```
### Role Authorization
```js
// Grant access to specific roles
exports.authorize = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            res.status(403)
            throw new Error('User role unauthorized to access this route')
        }

        next()
    }
}
```
### Relashionships
> In the model add a ref
```js
user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
}
```
> In the controller
```js
    req.body.user = req.user._id

    // Check for published bootcamp
    const publishedBootcamp = await Bootcamp.findOne({ user: req.user._id })

    // If user is admin, the can publish as many bootcamps as needed
    if (publishedBootcamp && !req.user.role === 'admin') {
        res.status(400)
        throw new Error('You have already published a bootcamp')
    }
```
### Owenership
```js
if ((bootcamp.user.toString() !== req.user._id) && req.user.role !== 'admin') {
    res.status(401)
    throw new Error('User not authorized to update this bootcamp')
} 
```
### Get user profile
```js
// @desc        Get User's Profile
// @router      GET /api/v1/auth/me
// @access      Private
exports.getMe = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)

    res.status(200).json({ success: true, data: user })
})
```
### Update user profile
```js

// @desc        Update user details
// @router      PUT /api/v1/auth/update
// @access      Private
exports.updateProfile = asyncHandler(async (req, res) => {
    const { name, email, currentPassword, newPassword } = req.body
    
    const user = await User.findById(req.user._id).select('+password')

    if (user) {
        user.name = name || req.user.name
        user.email = email || req.user.email

        if (currentPassword && newPassword) {
            if (!(await user.matchPassword(currentPassword))) {
                res.status(401)
                throw new Error('Password is incorrect')
            } else {
                user.password = newPassword

                await user.save()

                sendTokenResponse(user, 200, res)
            }
        }
    } else {
        res.status(404)
        throw new Error('Could not find user')
    }
})
```
### Set Authorization headers automatically
> In `login` and `register` routes in Postman, in the `Tests` tab
```js
pm.environment.set('TOKEN', pm.response.json().token)
```
<br/>
<br/>

## Password Recovery
### Forgot Password
> Add `resetPasswordToken` and `resetPasswordExpire` fields to the `user` model

> Add `getResetToken` method in the `user` model
```js
    const resetToken = crypto.randomBytes(20).toString('hex')
    
    // Hash and save resetToken
    this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    
    // Set the expiration to 10 minutes
    this.resetPasswordExpire = Date.now() + 10 * 60 * 1000
    
    // return the original reset token before hash
    return resetToken
```
> In `authController` add `forgotPassword` method
```js
// @desc        Forgot password
// @router      GET /api/v1/auth/forgot-password
// @access      Public
exports.forgotPassword = asyncHandler(async (req, res) => {
    const user = await User.findOne({ email: req.body.email })

    if (!user) {
        res.status(404)
        throw new Error('There is no user with this email')
    }

    // Get reset password token
    const resetToken = user.getResetToken()

    await user.save({ validateBeforeSave: false })

    res.status(200).json(user)
})

```
### Send Email
> Install `nodemailer`

> In `.env`
```js
SMTP_HOST="smtp.mailtrap.io"
SMTP_PORT=2525
SMTP_EMAIL=email"
SMTP_PASSWORD="pwd"
FROM_EMAIL=noreply@api.io
FROM_NAME=api-docs
```
> In `utils/sendEmail.js`
```js
const nodemailer = require('nodemailer')

const sendEmail = async (options) => {
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        auth: {
            user: process.env.SMTP_EMAIL,
            pass: process.env.SMTP_PASSWORD
        }
    })

    const message = {
        from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`,
        to: options.email,
        subject: options.subject,
        text: options.message,
    }

    await transporter.sendMail(message)
}

module.exports = sendEmail
```
> In `authController` `forgotPassword` method, after saving the `resetToken` to the data base, send the email
```js
    // Create reset URL
    const resetUrl = `${req.protocol}://${req.get('host')}/api/v1/resetpassword/${resetToken}`

    try {
        await sendEmail({
            email: user.email,
            subject: 'Password reset token',
            message: `reset your password : ${resetUrl}`
        }) 

        res.status(200).json({success: true, data: 'Email sent'})
    } catch (error) {
        user.resetPasswordToken = undefined
        user.resetPasswordExpire = undefined

        await user.save({validateBeforeSave: false})

        res.status(500)
        throw new Error('Email could not be sent')
    }
```
### Reset Passowrd
> In `authController` add `resetPassword` method
```js

// @desc        Reset Password
// @router      PUT /api/v1/auth/reset-password/:resettoken
// @access      Public
exports.resetPassowrd = asyncHandler(async (req, res) => {
    // Hash the token
    const resetPasswordToken = crypto.createHash('sha256').update(req.params.resettoken).digest('hex')

    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
    })

    if (user) {
        // Set new password
        user.password = req.body.password

        user.resetPasswordToken = undefined
        user.resetPasswordExpire = undefined

        await user.save()

        sendTokenResponse(user, 200, res)
    } else {
        res.status(400)
        throw new Error('Invalid token')
    }
})
```
<br/>
<br/>

## Reviews
> Add `bootcamp` and `user` to the `Review` model

> Add index to prevent the user from submitting more than one review per bootcamp

> index will check in the `Review` collection whether there is a document that has fields `bootcamp` and `user` before creating the document, if not then it will be created 
```js
ReviewSchema.index({ bootcamp: 1, user: 1 }, { unique: true })
```
### Average Rating
```js
ReviewSchema.statics.getAverageRating = async(bootcampId) => {
    const obj = await this.aggregate([
        {
            $match: { bootcamp: bootcampId }
        },
        {
            $group: {
                _id: '$bootcamp',
                averageRating: { $avg: '$rating' }
            }
        }
    ])

    try {
        await this.model('bootcamp').findByIdAndUpdate(bootcampId, {
            averageRating: obj[0].averageRating
        })
    } catch (error) {
        console.log(error);
    }
}

ReviewSchema.post('save', function() {
    this.constructor.getAverageRating(this.bootcamp)
})

ReviewSchema.pre('remove', function() {
    this.constructor.getAverageRating(this.bootcamp)
})
```
<br/>
<br/>

## Advanced Results Middleware
```js
const advancedResults = (model, populate) => async (req, res, next) => {
    let query

    const exclude = ['select', 'sort', 'limit', 'page']

    let reqQuery = { ...req.query }

    exclude.forEach(param => delete reqQuery[param])
    
    let queryStr = JSON.stringify(reqQuery)

    queryStr = queryStr.replace(/\b(gt|gte|lt|lte|in)\b/g, match => `$${match}`)

    console.log(queryStr)

    query = model.find(JSON.parse(queryStr))

    if (req.query.select) {
        const fields = req.query.select.split(',').join(' ')
        query = query.select(fields)
    }

    if (req.query.sort) {
        const sortBy = req.query.sort.split(',').join(' ')
        query = query.sort(sortBy)
    } else {
        query = query.sort('-createdAt')
    }

    if (populate) {
        query = query.populate(populate)
    }

    // Pagination
    const page = parseInt(req.query.page, 10) || 1
    const limit = parseInt(req.query.limit, 10) || 2
    const startIndex = (page - 1) * limit
    const endIndex = page * limit
    const total = await model.countDocuments()

    query = query.skip(startIndex).limit(limit)

    const result = await query

    // pagination result
    const pagination = {}

    if (endIndex < total) {
        pagination.next = {
            page: page + 1,
            limit,
        }
    }

    if (startIndex > 0) {
        pagination.prev = {
            page: page - 1,
            limit,
        }
    }
    
    res.advancedResults = {
        success: true,
        data: result,
        count: result.length,
        pagination,
    }

    next()
}

module.exports = advancedResults
```
> In the resource Router, include `advancedResults` and the model for the target resource
```js
router.route('/').get(advancedResults(Review, {
    path: 'bootcamp',
    select: 'name description'
}), getReviews)
```
> In the controller
```js
res.status(200).json(res.advancedResults)
```
<br/>
<br/>

## API Security
### NoSql Injections
#### Vulnarability
> If we send a post request to `/api/v1/auth/login` with body
```js
"email": {"$gt": ""},
"password": any-password-that-exists-in-the-db-even-if-it-is-not-encrypted
```
#### Solution
> Install `express-mongo-sanitizer` and in `server`
```js
const mongoSanitizer = require('express-mongo-sanitizer')
app.use(mongoSanitizer())
```

### XSS Attacks
#### Vulnarability
> If we enter data with harmful tags
```js
"name": "<script>alert('XSS')<script>"
```
#### Solution
> Install `xss-clean` and in `server`
```js
const xss = require('xss-clean')
app.use(xss())
```

### Security Headers
> Install `helmet`, and in `server`
```js
const xss = require('helmet')
app.use(helmet())
```

### Rate Limiting
> Install `express-rate-limit`, and in `server`
```js
const rateLimit = require('express-rate-limit')

// 100 requests per 10 minutes 
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 100,
})

app.use(limiter)
```

### Prevent HTTP param pollution attacks (HPP)
> Install `hpp`, and in `server`
```js
const hpp = request('hpp')
app.use(hpp())
```

### Enable CORS
> Install `cors`, and in `server`
```js
const cors = request('cors')
app.use(cors())
```


<br/>
<br/>
<br/>
<br/>
<br/>

## Data Seeder Script
> configurate the `.env` file inside the seeding script

> connect to the database

> Import the models

> Add `exportData` and `destroyData` functions

> Configurate the `process.argv[2]` options

```js
const fs = require('fs')
const path = require('path')
const mongoose = require('mongoose')
require('dotenv').config()
require('colors')

// Load models
const Bootcamp = require('./models/Bootcamp')

// Connect to db
const connect = async() => {
    try {
        await mongoose.connect(process.env.MONGO_URI)
    } catch (error) {
        console.log(error)
    }
}

connect()


// Read JSON files
const bootcamps = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'data', 'bootcamps.json'), 'utf-8'))

// Export data into DB
const importData = async() => {
    try {
        await Bootcamp.create(bootcamps)

        console.log('Data Exported Successfully'.green.inverse);
    } catch (error) {
        console.error(error)
    }
}

// Delete Data from DB
const deleteData = async() => {
    try {
        await Bootcamp.deleteMany()

        console.log('Data Destroyed Successfully'.red.inverse);
    } catch (error) {
        console.error(error)
    }
}

// Commands
if (process.argv[2] === '-e') {
    importData()
} else if (process.argv[2] === '-d') {
    deleteData()
}
```
