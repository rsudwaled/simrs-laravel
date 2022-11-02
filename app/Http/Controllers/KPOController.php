<?php

namespace App\Http\Controllers;

use App\Models\ICD10;
use Illuminate\Http\Request;

class KPOController extends Controller
{
    public function index()
    {
        //
        $roles = ICD10::limit(10)->get();
        return view('simrs.kpo_create', compact(['roles']));
    }

    public function create()
    {
        //
    }

    public function store(Request $request)
    {
        //
    }

    public function show($id)
    {
        //
    }

    public function edit($id)
    {
        //
    }

    public function update(Request $request, $id)
    {
        //
    }

    public function destroy($id)
    {
        //
    }
}
